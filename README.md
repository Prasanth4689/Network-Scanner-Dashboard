# ⚡ NetPulse (InfraSight) v3.0.0
### Smart Real-Time Network Asset Discovery & Security Dashboard

[![Live Demo](https://img.shields.io/badge/Demo-Vercel%20Live-00f0ff?style=for-the-badge&logo=vercel&logoColor=white)](https://network-scanner-dashboard-xt32.vercel.app/)
[![Version](https://img.shields.io/badge/Version-v3.0.0-39ff14?style=for-the-badge)](https://github.com/Prasanth4689/Network-Scanner-Dashboard)
[![Node.js](https://img.shields.io/badge/Backend-Node.js%20%7C%20Express-green?style=for-the-badge&logo=node.js&logoColor=white)](https://nodejs.org/)
[![WebSockets](https://img.shields.io/badge/Real--Time-WebSockets%20(ws)-blueviolet?style=for-the-badge)](https://github.com/websockets/ws)
[![UI](https://img.shields.io/badge/UI-Cyberpunk%20Glassmorphism-ff007f?style=for-the-badge)]()

---

## 🌐 Live Website

- **Hosted Cloud Deployment**: [https://network-scanner-dashboard-xt32.vercel.app/](https://network-scanner-dashboard-xt32.vercel.app/)
- **Academic Project Report**: [View Full Report (Markdown)](docs/PROJECT_REPORT.md) | [Download Word Document (DOCX)](docs/InfraSight_Project_Report.docx)

---

## 📖 Project Overview (For Professor & Evaluators)

**NetPulse** (also documented as **InfraSight**) is an advanced, real-time network reconnaissance and asset management dashboard. It bridges the gap between complex command-line networking tools (like `arp`, `ping`, and `nmap`) and visual security auditing by presenting deep network telemetry inside a responsive **cyberpunk glassmorphic** web interface.

In security assessments and penetration testing, the initial **reconnaissance phase** is crucial: you cannot protect or evaluate systems you cannot see. NetPulse continuously discovers connected devices, identifies their hardware manufacturers, measures connection latency, audits exposed ports, calculates network health ratings, and alerts administrators when new devices join or leave the network.

---

## 🚀 Key Features

### 1. 🔄 Real-Time WebSocket Continuous Scanning
- Automatically scans the network every **5 seconds** in the background.
- Employs a built-in **diff engine** that tracks join/leave events.
- Broadcasts instant notifications (toast alerts and live event log) whenever a device connects or disconnects.

### 2. 📱 Deep Device Discovery & Classification
- Discovers all active devices across the IPv4 subnet.
- Identifies **IP address, physical MAC address, network latency (ms)**, and **online status** (Active vs. Shielded).
- Resolves hardware manufacturer OUIs (Apple, Samsung, Intel, Raspberry Pi, etc.).
- Automatically classifies devices into categories (Router, Mobile, PC, IoT, Server).

### 3. 🛡️ Network Health & Security Posture Rating
- Dedicated **Security Tab** in the sidebar.
- Computes an automated **0–100 Health Score** with letter grades (**A+**, **A**, **B**, **C**, **D**).
- Dynamic weighted formula evaluates:
  - **Latency Score** (50%): Average response time across endpoints.
  - **Reachability** (30%): Percentage of active vs. shielded/offline hosts.
  - **Network Density** (20%): Subnet utilization balance.

### 4. 🔍 Device Details Modal & Signal Analysis
- Click the **Details** button on any device to open a deep inspection modal.
- Displays calculated **Wi-Fi Signal Strength** bars in **dBm** (-30 to -80 dBm).
- Records **First Seen** session timestamps.
- One-click shortcuts to **Audit Ports**, **Lookup DNS**, or **Trace Route** for that specific IP.

### 5. 🛣️ Advanced Networking Tools
- **Route Trace (Traceroute)**: Maps each intermediate hop from the host to any destination IP or domain with hop-by-hop latency and visual path connectors.
- **Reverse DNS Lookup**: Resolves internal or external IP addresses to human-readable hostnames.
- **Session Statistics**: Live tracking of total scans performed, peak connected devices, server uptime, and total network events.

### 6. 🔓 TCP Port Auditing
- Quick-scan common service ports (FTP 21, SSH 22, Telnet 23, HTTP 80, HTTPS 443, SMB 445, RDP 3389, HTTP-Alt 8080).
- Highlights potential security risks, open services, and unnecessary open attack vectors.

### 7. 🕸️ Interactive Topology Map & Tools
- Graphical network map showing relationships between the default gateway and all connected clients with pulsating status rings.
- **Subnet Calculator**: Instant calculation of network addresses, broadcast IPs, subnet masks, and total usable hosts.
- **Data Export**: One-click export of current network asset inventory to **CSV** and **JSON**.

---

## ⚡ Real Scanning vs. Cloud Simulator Mode

| Feature | Local Laptop Execution (`localhost:3000`) | Hosted Cloud Deployment (Vercel) |
| :--- | :--- | :--- |
| **Network Adapter** | Uses your laptop's physical Wi-Fi / Ethernet | Runs in Vercel's cloud serverless sandbox |
| **Real Device Scanning** | **Yes** — runs physical OS `arp -a`, ICMP `ping` | Not allowed by cloud security sandboxes |
| **Simulator Mode** | Optional (toggle in sidebar) | **Active by default** for live interactive demo |
| **Hotspot Device Detection**| **Yes** — Detects connected phones & devices | Displays realistic simulated demo assets |
| **WebSockets** | Full persistent duplex WebSocket connection | Falls back to REST API polling |

> **Note for Testing with Real Devices**:  
> To scan your real Wi-Fi network or mobile phone hotspot, run the application locally on your computer (see steps below) and toggle off **Simulator Mode** in the left sidebar!

---

## 💻 How to Run Locally

### Prerequisites
- [Node.js](https://nodejs.org/) (version 18 or higher)
- Windows, macOS, or Linux

### Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/Prasanth4689/Network-Scanner-Dashboard.git
   cd Network-Scanner-Dashboard
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the server:
   ```bash
   npm start
   ```

4. Open your web browser and navigate to:
   ```
   http://localhost:3000
   ```

5. **To scan real devices**: Turn off the **Simulator Mode** switch in the sidebar. The dashboard will immediately scan your real network adapter and display your connected devices!

---

## 📡 API Reference

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/scan` | `GET` | Executes a subnet discovery sweep (supports `?mock=true/false`) |
| `/api/health-score` | `GET` | Returns 0–100 health score, breakdown, and letter grade |
| `/api/traceroute` | `GET` | Runs hop trace to `?targetIp=X` |
| `/api/dns-lookup` | `GET` | Resolves reverse DNS hostnames for `?targetIp=X` |
| `/api/stats` | `GET` | Returns aggregate session stats (uptime, scans, peak devices) |
| `/api/portscan` | `POST` | Probes common TCP ports on a target IP |
| `/api/ping` | `POST` | Measures round-trip ICMP latency to a target IP |
| `/api/network-info` | `GET` | Retrieves local IP, subnet CIDR, netmask, and broadcast |
| `/api/events` | `GET` | Retrieves recent network join/leave/status events |
| `/api/scanner-mode`| `POST` | Toggles server between simulator mode and real mode |

---

## 🏗️ Project Architecture

```
Network-Scanner-Dashboard/
├── api/
│   └── index.js             # Vercel serverless entrypoint
├── docs/
│   ├── PROJECT_REPORT.md    # Full academic project report (Markdown)
│   └── InfraSight_Project_Report.docx # Word document report
├── public/
│   ├── index.html           # Main dashboard interface
│   ├── style.css            # Cyberpunk glassmorphic design system
│   └── app.js               # Frontend controller, WebSocket client, UI logic
├── server.js                # Express backend, WebSocket server, ARP & Ping engine
├── package.json             # Project dependencies & npm scripts
├── vercel.json              # Vercel deployment configuration
└── README.md                # Project documentation
```

---

## 📜 License & Academic Integrity

This project is created for educational, research, and network administrative purposes under the **MIT License**.  
Always obtain proper authorization before scanning or conducting security evaluations on networks you do not own or manage.
