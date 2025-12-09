# Packet Tracer API

This project simulates how a network packet travels through a virtual network.  
It includes DNS resolution, routing using longest-prefix match, TTL handling, and firewall rule processing.  
The API returns a hop-by-hop trace showing the decisions taken at each step.

---

## 📁 Project Structure

Gpp-task-3/
├── app.js
├── dnsConfig.json
├── routesConfig.json
├── firewallConfig.json
├── package.json
└── node_modules/


## 🚀 How to Run

1. Install dependencies:
npm install
Start the server:

npm start
Server runs at:
➡️ http://localhost:3000

Open the browser at http://localhost:3000/ to check the server is running.


Endpoint: POST /trace

Send a JSON payload describing a packet:

{
  "sourceIp": "192.168.1.50",
  "destination": "www.example.com",
  "destPort": 80,
  "protocol": "TCP",
  "ttl": 4
}



Example Successful Response
[
  { "location": "DNS Resolver", "action": "CNAME: www.example.com → example.com" },
  { "location": "DNS Resolver", "action": "Resolved www.example.com to 10.0.0.10" },
  { "location": "Router-1", "action": "Forwarded towards 10.0.0.10 via next-hop 10.0.0.1 on eth0, TTL now 3" },
  { "location": "Firewall", "action": "Packet allowed by rule #2" },
  { "location": "Destination Host", "action": "Packet delivered to 10.0.0.10:80 over TCP" }
]


⚠️ Error Responses
NXDOMAIN
[
  { "location": "DNS Resolver", "action": "NXDOMAIN: unknown.site not found" }
]

Firewall Block
[
  { "location": "Firewall", "action": "Packet blocked by rule #1 (protocol=TCP, port=22-22)" }
]

TTL Exceeded
[
  { "location": "Router-0", "action": "Time To Live (TTL) exceeded. Packet dropped." }
]


Configuration Files
dnsConfig.json
{
  "records": [
    { "type": "A", "name": "example.com", "address": "10.0.0.10" },
    { "type": "CNAME", "name": "www.example.com", "alias": "example.com" }
  ]
}

routesConfig.json
{
  "routes": [
    { "cidr": "10.0.0.0/24", "nextHop": "10.0.0.1", "interface": "eth0", "routerName": "Router-1" },
    { "cidr": "0.0.0.0/0", "nextHop": "192.168.1.1", "interface": "eth1", "routerName": "Default-Gateway" }
  ]
}

firewallConfig.json
{
  "rules": [
    { "id": 1, "action": "deny", "protocol": "TCP", "source": "0.0.0.0/0", "destPortRange": [22, 22] },
    { "id": 2, "action": "allow", "protocol": "TCP", "source": "0.0.0.0/0", "destPortRange": [0, 65535] }
  ]
}