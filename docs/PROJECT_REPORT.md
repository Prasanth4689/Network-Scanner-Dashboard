# InfraSight: Smart Network Asset Discovery & Visualization

> **Academic Project Report**  
> *A Smart Network Asset Discovery, Reconnaissance, and Visualization System*

---

## 1. Executive Summary

**InfraSight** (deployed as **NetPulse**) is a smart network asset discovery and visualization system designed to provide comprehensive visibility into devices connected to a local network. The system combines real-time network discovery, device identification, port scanning, latency monitoring, subnet analysis, and network topology visualization into a single, cohesive dashboard.

In the context of penetration testing and vulnerability analysis, identifying active assets is one of the first and most critical stages of reconnaissance. Unknown devices, exposed services, and unnecessary open ports significantly increase the attack surface of an enterprise or home network. InfraSight assists security analysts and network administrators in obtaining an organized, real-time inventory of network assets and their operational characteristics before performing deeper security assessments.

The system is built on a **Node.js** and **Express.js** backend coupled with a modern **HTML5, CSS3, and JavaScript** front-end. Network telemetry is gathered using foundational techniques such as:
- ARP-based local device discovery
- ICMP echo requests (ping) for latency measurement
- TCP socket port scanning for exposed services
- MAC address OUI identification for hardware vendor resolution
- Subnet and CIDR calculation
- WebSocket real-time event streaming

The platform includes both a live network scanning engine for physical adapters and a simulator mode for cloud demonstrations and environments without low-level packet capture privileges.

---

## 2. Introduction

Modern computer networks host an increasingly diverse array of interconnected devices: workstations, mobile smartphones, wireless access points, IoT sensors, network printers, and dedicated servers. Maintaining real-time visibility over all active endpoints is fundamental to maintaining an effective security posture.

From an offensive security and penetration-testing standpoint, asset discovery constitutes the initial reconnaissance phase. Before assessing vulnerabilities, security professionals must establish:
- Which physical and virtual systems are reachable
- What IP and MAC addresses are assigned
- Which ports and transport services are listening
- The underlying hardware manufacturer and operating profile

Traditional command-line utilities (such as `arp`, `ping`, and raw socket scanners) provide rich technical data but present results in fragmented, terminal-based outputs that can be cumbersome to parse. InfraSight addresses this visibility gap by synthesizing multi-layer network discovery into an interactive, centralized dashboard.

---

## 3. Background & Theoretical Concepts

### 3.1 Network Asset Discovery
Asset discovery maps active hosts on a local subnet using broadcast and unicast protocol interactions. Key collected metadata includes IPv4 addresses, Hardware (MAC) addresses, host availability, and vendor identifiers.

### 3.2 Network Reconnaissance
Reconnaissance is the systematic gathering of intelligence regarding target network ranges, accessible hosts, and perimeter defenses. InfraSight performs passive and active discovery within permitted subnet boundaries.

### 3.3 TCP Port Scanning
Network ports serve as transport-layer multiplexing endpoints. Identifying open TCP ports helps map active daemons (e.g., HTTP on 80, HTTPS on 443, SSH on 22, SMB on 445) and assess exposed service attack surfaces.

### 3.4 ICMP Latency Monitoring
Internet Control Message Protocol (ICMP) echo requests verify host reachability and quantify round-trip response time (RTT), providing real-time quality-of-service and responsiveness metrics.

### 3.5 MAC Address & OUI Identification
Every standard Ethernet and Wi-Fi interface carries a 48-bit MAC address. The first 24 bits designate the Organizationally Unique Identifier (OUI) assigned by the IEEE, allowing instant classification of device manufacturers (e.g., Apple, Samsung, Intel, Raspberry Pi).

### 3.6 Topology Visualization
Visualizing asset relationships in radial, hierarchical, or force-directed graph structures accelerates anomaly detection, pinpointing rogue or unclassified nodes at a glance.

---

## 4. Problem Statement & Objectives

### 4.1 Existing Problem
Dynamic networks frequently experience undocumented device connections (Bring-Your-Own-Device policies, transient guest nodes, unauthorized IoT gadgets), resulting in fragmented visibility and "shadow IT" attack vectors.

### 4.2 Key Limitations of Conventional Tools
1. **Tool Fragmentation**: Requires running separate commands for ARP tables, ping sweeps, DNS queries, and port checks.
2. **Lack of Continuous Telemetry**: Standard CLI runs give point-in-time snapshots rather than continuous join/leave notifications.
3. **Cognitive Overload**: Raw text dumps lack visual grouping, vendor badges, or relationship mapping.
4. **Cloud/Platform Incompatibility**: Strict cloud environments (e.g., Vercel serverless functions) lack raw ICMP/ARP privileges, necessitating intelligent simulation fallback.

### 4.3 Proposed Solution
InfraSight delivers a unified dashboard incorporating:
- Automated Subnet Range Calculation
- Multi-threaded Host Discovery (ARP + ICMP)
- OUI Manufacturer Lookup & Device Categorization
- Targeted TCP Port Auditing
- Continuous WebSocket State Diffing (Join/Leave Alerts)
- Interactive Network Topology Visualization
- Network Health & Security Scoring
- Hop-by-Hop Route Trace (Traceroute) & Reverse DNS Lookup
- CSV & JSON Data Export

---

## 5. System Architecture & Methodology

```
+-------------------------------------------------------------+
|                  Client Browser (SPA UI)                    |
|   Dashboard | Security Tab | Topology Map | Port Scanner    |
+-------------------------------------------------------------+
       |                                              ^
   REST Requests                                WebSocket
 (POST/GET APIs)                            Real-Time Updates
       v                                              |
+-------------------------------------------------------------+
|                  Node.js / Express Server                   |
|   - Real-time Scanner Loop (5s interval)                    |
|   - Diff Engine (detects Join / Leave / Status Changes)     |
|   - In-memory State & Event History Store                   |
+-------------------------------------------------------------+
       |                         |                    |
   ARP Discovery           ICMP Latency          TCP Sockets
 (OS CLI / arp -a)        (Ping Engine)        (Port Scanner)
       |                         |                    |
+-------------------------------------------------------------+
|                 Underlying Local Network                    |
|   Routers | Phones | Workstations | IoT | Gateway Nodes     |
+-------------------------------------------------------------+
```

### 5.1 Architecture Components
1. **Frontend Dashboard**: Single-page application styled with responsive CSS glassmorphism, animated SVG health score meters, Lucide icons, and modal dialogs.
2. **REST API**: Exposes endpoints for ad-hoc subnet discovery, port scanning, traceroute, reverse DNS, and aggregate statistics.
3. **WebSocket Engine**: Establishes persistent full-duplex communication (`ws://`), emitting `device_joined`, `device_left`, and `device_updated` events.
4. **Diff Engine**: Computes device delta states on every scan cycle, logging timestamped events and triggering browser toast alerts.
5. **Hybrid Engine (Real + Simulator)**: Seamlessly toggles between physical OS network scans (`arp -a`, `ping`, `tracert`) and a deterministic mock pool for safe demonstrations.

---

## 6. Functional Capabilities & Feature Matrix

| Feature | Description | Implementation |
| :--- | :--- | :--- |
| **Real-Time Discovery** | Detects active subnet devices every 5 seconds | Windows ARP table parsing & IP sweeps |
| **Join/Leave Notifications** | Instant alerts when a host enters or departs | WebSocket broadcast & client-side toasts |
| **Network Health Score** | 0–100 posture rating with letter grade (A+ to D) | Weighted formula: Latency (50%), Reachability (30%), Density (20%) |
| **Device Classification** | Assigns icons & categories (Mobile, PC, Router, IoT) | Vendor OUI heuristics & hostname parsing |
| **Port Auditing** | Scans common attack vectors (Ports 21, 22, 80, 443, etc.) | Asynchronous Node.js `net.Socket` connection probes |
| **Device Details Modal** | Inspects MAC, latency, signal strength (dBm), first seen | Modal UI with quick actions (Ping, Trace, DNS) |
| **Route Trace Analysis** | Measures multi-hop latency to internet destinations | Windows `tracert` execution with fallback simulation |
| **Reverse DNS Resolution** | Resolves local and remote IPs to domain hostnames | Node.js `dns.reverse()` integration |
| **Network Topology Map** | Interactive node diagram showing gateway-to-device links | CSS radial layout with animated SVG pulse rings |
| **Subnet Calculator** | Computes network address, broadcast IP, and host counts | `ip` library bitmask analysis |
| **Export Formats** | Downloads device inventory for documentation | Client-side CSV & JSON blob generation |

---

## 7. Security & Reconnaissance Analysis

### 7.1 Attack Surface Reduction
By maintaining an accurate, updated asset list, system administrators can immediately spot unauthorized devices (such as rogue Wi-Fi access points or unauthorized laptops).

### 7.2 Service Hardening
The integrated port audit identifies listening services that should either be disabled (e.g., Telnet on port 23, unencrypted HTTP on port 80) or firewalled behind access control lists.

### 7.3 Responsible Use & Ethical Constraints
InfraSight is engineered for defensive reconnaissance, network administration, and educational security labs. Port scanning and network mapping must only be conducted on networks where explicit administrative authorization has been granted.

---

## 8. Evaluation & Verification

### 8.1 Verification in Physical & Hotspot Environments
The application was evaluated across local Wi-Fi networks and mobile hotspot configurations:
- **Hotspot Device Detection**: The host machine correctly identified the gateway mobile device and resolved IP, MAC address, and latency characteristics.
- **WebSocket Throughput**: Continuous 5-second delta updates maintained sub-10ms UI responsiveness with negligible CPU overhead.
- **Port Audit Latency**: Asynchronous connection timeouts (1.5s per port) prevented interface lockups during closed-port sweeps.

### 8.2 Cloud Demonstration (Vercel)
Due to serverless container isolation preventing raw ICMP/ARP execution, the built-in **Simulator Mode** automatically provides deterministic, realistic device profiles so evaluators and professors can examine full dashboard functionality in hosted browser sessions.

---

## 9. Conclusion & Future Scope

InfraSight successfully combines essential network reconnaissance methodologies into a high-performance, accessible web dashboard. It bridges the gap between raw low-level networking commands and actionable visual intelligence.

### Future Scope:
- Integration of Nmap service and OS fingerprinting signatures (`-sV`, `-O`).
- Automated CVE vulnerability mapping against discovered port services.
- SNMP (Simple Network Management Protocol) v2/v3 query integration.
- Automated email/Slack alerting on unknown MAC address detection.

---

## 10. References
1. **RFC 826** — *An Ethernet Address Resolution Protocol (ARP)*.
2. **RFC 792** — *Internet Control Message Protocol (ICMP)*.
3. **RFC 793** — *Transmission Control Protocol (TCP)*.
4. **Node.js Documentation** — *Net, Child Process, and DNS APIs*.
5. **OWASP Foundation** — *Network Reconnaissance and Asset Mapping Guide*.
6. **NIST SP 800-115** — *Technical Guide to Information Security Testing and Assessment*.
7. **IEEE Standards Association** — *Guidelines for Organizationally Unique Identifier (OUI) Registration*.
