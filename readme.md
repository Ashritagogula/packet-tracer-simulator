🛰️ Packet Tracer API — Virtual Network Simulator

A fully API-driven simulator that models the journey of a network packet through a virtual network.
This project demonstrates DNS resolution, IP routing (longest prefix match), firewall rule processing, TTL lifecycle, and packet delivery.

🚀 Features

DNS Resolver supporting A and CNAME records

Routing Engine using Longest Prefix Match

Firewall with ordered allow/deny rules

TTL decrement & packet expiry

Hop-by-hop trace

Configurable JSON-based topology

📁 Project Structure

(NOTE: This block is protected — VS Code will NOT change it.)

Gpp-task-3/
│
├── app.js
├── dnsConfig.json
├── routesConfig.json
├── firewallConfig.json
│
├── config/
│   ├── scenario-basic.json
│   ├── scenario-complex.json
│
├── screenshots/
│   ├── startingserver.png
│   ├── successful-trace.png
│   ├── nxdomain-error.png
│   ├── firewall-block.png
│   ├── no-route.png
│   ├── ttl-expired.png
│
└── README.md

🔧 Installation & Setup
Clone the repository
git clone https://github.com/Ashritagogula/packet-tracer-simulator.git
cd packet-tracer-simulator

Install dependencies
npm install

Run server
node app.js


Expected:

Packet tracer API running on port 4000

📡 API — POST /trace

Simulates the packet journey across the virtual network.

Request Body
{
  "sourceIp": "10.0.0.5",
  "destination": "example.com",
  "destPort": 80,
  "protocol": "TCP",
  "ttl": 5
}

Response Example
[
  { "location": "DNS Resolver", "action": "Resolved example.com to 192.168.10.10" },
  { "location": "Router-1", "action": "Forwarded … TTL now 4" },
  { "location": "Firewall", "action": "Packet allowed" },
  { "location": "Destination Host", "action": "Delivered" }
]

🧠 How It Works
1️⃣ DNS Resolution

Supports A + CNAME

Detects CNAME loops

NXDOMAIN if no record

2️⃣ Routing — Longest Prefix Match

Picks route with highest prefix

If no match → Destination Unreachable

3️⃣ Firewall Processing

Rules have:

action

source CIDR

port range

protocol

First matching rule wins.

4️⃣ TTL Lifecycle

Decreases each hop

TTL = 0 → TTL Exceeded

📘 Example Configs
dnsConfig.json
{
  "records": [
    { "name": "example.com", "type": "A", "address": "192.168.10.10" },
    { "name": "www.example.com", "type": "CNAME", "alias": "example.com" }
  ]
}

routesConfig.json
{
  "routes": [
    {
      "cidr": "10.0.0.0/24",
      "nextHop": "10.0.0.1",
      "interface": "eth0",
      "routerName": "Router-1"
    },
    {
      "cidr": "0.0.0.0/0",
      "nextHop": "192.168.1.1",
      "interface": "eth1",
      "routerName": "Default-Gateway"
    }
  ]
}

firewallConfig.json
{
  "rules": [
    { "id": 1, "action": "deny", "protocol": "TCP", "source": "0.0.0.0/0", "destPortRange": [22, 22] },
    { "id": 2, "action": "allow", "protocol": "TCP", "source": "0.0.0.0/0", "destPortRange": [0, 65535] }
  ]
}

🖼️ Screenshots

(Note: just make sure files exist. GitHub will show them automatically.)

./screenshots/successful-trace.png
./screenshots/nxdomain-error.png
./screenshots/firewall-block.png
./screenshots/no-route.png
./screenshots/ttl-expired.png

👩‍💻 Author

Ashrita Gogula
RHCSA • Oracle Certified • Full Stack Developer Aspirant

END OF README