import express from "express";
import fs from "fs";

const app = express();
app.use(express.json());

// ---------- Load configs at startup ----------
const dnsConfig = JSON.parse(fs.readFileSync("./dnsConfig.json", "utf-8"));
const routesConfig = JSON.parse(fs.readFileSync("./routesConfig.json", "utf-8"));
const firewallConfig = JSON.parse(fs.readFileSync("./firewallConfig.json", "utf-8"));

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

// ---------- DNS Resolver ----------
function resolveHostname(hostname, trace) {
  let current = hostname;
  const visited = new Set();

  while (true) {
    if (visited.has(current)) {
      trace.push({
        location: "DNS Resolver",
        action: `CNAME loop detected for ${current}`
      });
      return null;
    }
    visited.add(current);

    const record = dnsConfig.records.find(r => r.name === current);
    if (!record) {
      trace.push({
        location: "DNS Resolver",
        action: `NXDOMAIN: ${current} not found`
      });
      return null;
    }

    if (record.type === "A") {
      trace.push({
        location: "DNS Resolver",
        action: `Resolved ${hostname} to ${record.address}`
      });
      return record.address;
    } else if (record.type === "CNAME") {
      trace.push({
        location: "DNS Resolver",
        action: `CNAME: ${current} → ${record.alias}`
      });
      current = record.alias;
    } else {
      trace.push({
        location: "DNS Resolver",
        action: `Unsupported DNS type for ${current}`
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
          action: `Packet blocked by rule #${rule.id} (protocol=${rule.protocol}, port=${minPort}-${maxPort})`
        });
        return false;
      } else {
        trace.push({
          location: "Firewall",
          action: `Packet allowed by rule #${rule.id}`
        });
        return true;
      }
    }
  }

  // Default: allow if no rule matched
  trace.push({
    location: "Firewall",
    action: "No matching rule, default allow"
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
        "Missing or invalid fields. Required: sourceIp (string), destination (string), destPort (number), protocol (string), ttl (number)."
    });
  }

  const trace = [];
  let packet = {
    sourceIp,
    destIp: null,
    destPort,
    protocol,
    ttl
  };

  // 1️⃣ DNS Resolution (if destination is hostname)
  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(destination);
  if (isIp) {
    packet.destIp = destination;
    trace.push({
      location: "DNS Resolver",
      action: `Destination is already an IP: ${destination}`
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
        action: "Time To Live (TTL) exceeded. Packet dropped."
      });
      break;
    }

    const route = findBestRoute(packet.destIp);
    if (!route) {
      trace.push({
        location: `Router-${currentHop}`,
        action: `No route to host ${packet.destIp}. Destination unreachable.`
      });
      break;
    }

    // Decrement TTL for this hop
    packet.ttl -= 1;
    currentHop += 1;

    trace.push({
      location: route.routerName || `Router-${currentHop}`,
      action: `Forwarded towards ${packet.destIp} via next-hop ${route.nextHop} on ${route.interface}, TTL now ${packet.ttl}`
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
      action: `Packet delivered to ${packet.destIp}:${packet.destPort} over ${packet.protocol}`
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
