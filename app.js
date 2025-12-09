import express from "express";
import fs from "fs";

const app = express();
app.use(express.json());

// ---------- Safe JSON loader (removes BOM, prints raw file if parse fails) ----------
function loadJsonSafe(path) {
  try {
    const raw = fs.readFileSync(path, "utf8");
    const clean = raw.replace(/^\uFEFF/, "").trim();
    try {
      return JSON.parse(clean);
    } catch (err) {
      console.error(`Failed to parse JSON file: ${path}`);
      console.error("---- RAW FILE START ----");
      console.error(raw);
      console.error("---- RAW FILE END ----");
      throw err;
    }
  } catch (err) {
    console.error(`Error reading file ${path}:`, err.message || err);
    throw err;
  }
}

// ---------- Load configs at startup (use safe loader) ----------
const dnsConfigRaw = loadJsonSafe("./dnsConfig.json");
const routesConfig = loadJsonSafe("./routesConfig.json");
const firewallConfig = loadJsonSafe("./firewallConfig.json");

// Normalize dnsConfig into an array of records we can work with.
// Accepts formats:
//  - { records: [ ... ] }
//  - [ { name, type, address }, ... ]
//  - { hosts: { "example.com": "1.2.3.4", ... } }
let dnsRecords = [];

if (Array.isArray(dnsConfigRaw)) {
  dnsRecords = dnsConfigRaw;
} else if (dnsConfigRaw && Array.isArray(dnsConfigRaw.records)) {
  dnsRecords = dnsConfigRaw.records;
} else if (dnsConfigRaw && dnsConfigRaw.hosts && typeof dnsConfigRaw.hosts === "object") {
  dnsRecords = Object.entries(dnsConfigRaw.hosts).map(([name, address]) => ({
    name,
    type: "A",
    address,
  }));
} else if (dnsConfigRaw && typeof dnsConfigRaw === "object") {
  // If top-level values are strings (name -> ip), convert
  const maybe = Object.keys(dnsConfigRaw).filter(k => typeof dnsConfigRaw[k] === "string");
  if (maybe.length > 0) {
    dnsRecords = maybe.map(name => ({ name, type: "A", address: dnsConfigRaw[name] }));
  } else {
    dnsRecords = [];
  }
} else {
  dnsRecords = [];
}

console.log("Loaded dnsConfig (normalized records):");
console.log(JSON.stringify(dnsRecords, null, 2));

// ---------- Friendly root route ----------
app.get("/", (req, res) => {
  res.send("Packet Tracer API is running. Use POST /trace with JSON body.");
});

// ---------- IP helpers ----------
function ipToInt(ip) {
  return ip
    .split(".")
    .reduce((acc, octet) => (acc << 8) + Number(octet), 0) >>> 0;
}

function cidrToMask(prefix) {
  return prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
}

function ipInCidr(ip, cidr) {
  // cidr expected like "10.0.0.0/24"
  const [network, prefixStr] = cidr.split("/");
  const prefix = Number(prefixStr);
  const ipInt = ipToInt(ip);
  const netInt = ipToInt(network);
  const mask = cidrToMask(prefix);
  return (ipInt & mask) === (netInt & mask);
}

// ---------- DNS Resolver (robust) ----------
function resolveHostname(hostname, trace) {
  let current = hostname;
  const visited = new Set();

  while (true) {
    if (visited.has(current)) {
      trace.push({
        location: "DNS Resolver",
        action: `CNAME loop detected for ${current}`,
      });
      return null;
    }
    visited.add(current);

    // Find a record that matches by 'name' or 'hostname' or 'host'
    const record = dnsRecords.find(
      (r) =>
        (r.name && r.name === current) ||
        (r.hostname && r.hostname === current) ||
        (r.host && r.host === current)
    );

    if (!record) {
      trace.push({
        location: "DNS Resolver",
        action: `NXDOMAIN: ${current} not found`,
      });
      return null;
    }

    // If record looks like A (address present) -> resolve
    if (record.type === "A" || record.address || record.ip || record.value) {
      const addr = record.address || record.ip || record.value;
      if (!addr) {
        trace.push({
          location: "DNS Resolver",
          action: `Malformed A record for ${current}`,
        });
        return null;
      }
      trace.push({
        location: "DNS Resolver",
        action: `Resolved ${hostname} to ${addr}`,
      });
      return addr;
    } else if (record.type === "CNAME" || record.alias || record.target || record.cname) {
      const alias = record.alias || record.target || record.cname;
      if (!alias) {
        trace.push({
          location: "DNS Resolver",
          action: `Malformed CNAME record for ${current}`,
        });
        return null;
      }
      trace.push({
        location: "DNS Resolver",
        action: `CNAME: ${current} → ${alias}`,
      });
      current = alias;
    } else {
      trace.push({
        location: "DNS Resolver",
        action: `Unsupported DNS record format for ${current}`,
      });
      return null;
    }
  }
}

// ---------- Routing (Longest Prefix Match) ----------
function findBestRoute(destIp) {
  let bestRoute = null;
  let bestPrefix = -1;

  for (const route of routesConfig.routes) {
    const prefix = Number(route.cidr.split("/")[1] || 0);
    if (ipInCidr(destIp, route.cidr) && prefix > bestPrefix) {
      bestPrefix = prefix;
      bestRoute = route;
    }
  }

  return bestRoute;
}

// ---------- Firewall ----------
function applyFirewall(packet, trace) {
  for (const rule of firewallConfig.rules) {
    const proto = rule.protocol ? rule.protocol.toUpperCase() : "ANY";
    const protocolMatch =
      proto === "ANY" || proto === packet.protocol.toUpperCase();

    const sourceMatch = ipInCidr(packet.sourceIp, rule.source);
    const port = packet.destPort;
    const [minPort, maxPort] = rule.destPortRange;
    const portMatch = port >= minPort && port <= maxPort;

    if (protocolMatch && sourceMatch && portMatch) {
      if (rule.action.toLowerCase() === "deny") {
        trace.push({
          location: "Firewall",
          action: `Packet blocked by rule #${rule.id} (protocol=${rule.protocol}, port=${minPort}-${maxPort})`,
        });
        return false;
      } else {
        trace.push({
          location: "Firewall",
          action: `Packet allowed by rule #${rule.id}`,
        });
        return true;
      }
    }
  }

  // Default: allow if no rule matched
  trace.push({
    location: "Firewall",
    action: "No matching rule, default allow",
  });
  return true;
}

// ---------- Main /trace endpoint ----------
app.post("/trace", (req, res) => {
  const { sourceIp, destination, destPort, protocol, ttl } = req.body;

  // Basic input validation
  if (
    !sourceIp ||
    !destination ||
    typeof destPort !== "number" ||
    !protocol ||
    typeof ttl !== "number"
  ) {
    return res.status(400).json({
      error:
        "Missing or invalid fields. Required: sourceIp (string), destination (string), destPort (number), protocol (string), ttl (number).",
    });
  }

  const trace = [];
  let packet = {
    sourceIp,
    destIp: null,
    destPort,
    protocol,
    ttl,
  };

  // 1️⃣ DNS Resolution (if destination is hostname)
  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(destination);
  if (isIp) {
    packet.destIp = destination;
    trace.push({
      location: "DNS Resolver",
      action: `Destination is already an IP: ${destination}`,
    });
  } else {
    const resolved = resolveHostname(destination, trace);
    if (!resolved) {
      // NXDOMAIN already traced
      return res.json(trace);
    }
    packet.destIp = resolved;
  }

  // 2️⃣ Routing + TTL + Firewall simulation
  // We simulate router hops until TTL 0 or delivered/error
  let currentHop = 0;

  while (true) {
    if (packet.ttl <= 0) {
      trace.push({
        location: `Router-${currentHop}`,
        action: "Time To Live (TTL) exceeded. Packet dropped.",
      });
      break;
    }

    const route = findBestRoute(packet.destIp);
    if (!route) {
      trace.push({
        location: `Router-${currentHop}`,
        action: `No route to host ${packet.destIp}. Destination unreachable.`,
      });
      break;
    }

    // Decrement TTL for this hop
    packet.ttl -= 1;
    currentHop += 1;

    trace.push({
      location: route.routerName || `Router-${currentHop}`,
      action: `Forwarded towards ${packet.destIp} via next-hop ${route.nextHop} on ${route.interface}, TTL now ${packet.ttl}`,
    });

    // Firewall check at this hop
    const allowed = applyFirewall(packet, trace);
    if (!allowed) {
      // Blocked, stop simulation
      break;
    }

    // For this simulator, assume after one successful route+firewall we reach destination
    trace.push({
      location: "Destination Host",
      action: `Packet delivered to ${packet.destIp}:${packet.destPort} over ${packet.protocol}`,
    });
    break;
  }

  res.json(trace);
});

// ---------- Start server ----------
const PORT = 4000;
app.listen(PORT, () => {
  console.log(`Packet tracer API running on port ${PORT}`);
});
