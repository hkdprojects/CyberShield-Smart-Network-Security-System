# CyberShield: Real-Time Network Intrusion Detection & Prevention System (IDPS)

CyberShield is an intelligent, software-oriented network security gateway designed for deployment on wireless access points. By combining traditional rule-based signatures with a behavioral machine learning pipeline (Isolation Forest), CyberShield analyzes forwarding-layer traffic to detect, classify, and isolate malicious nodes in real time before they compromise network resources.

---

## 🛠️ Hardware Requirements & Infrastructure

To construct an isolated Local Area Network (LAN) capable of deep packet inspection and traffic manipulation, the monitoring gateway requires a dedicated secondary network interface:

* **Wireless USB Adapter**: Must feature an **Atheros AR9271** chipset (or equivalent).
* **Capabilities**: The driver stack must explicitly support Linux **Monitor Mode** and **Packet Injection**.

---

## 🏗️ System Architecture & Mechanics

CyberShield operates by intercepting data at the Linux kernel packet forwarding boundary. When a client device connects to the hotspot, its behavior is tracked across multiple operational layers:

1. **Traffic Sniffing Layer (`sniffer.py`)**: Captures raw packet streams traversing the gateway interface (`ap0`) using low-level socket abstractions.
2. **Feature Extraction Layer**: Normalizes packet bursts into structured behavioral vectors (packet sizes, transmission protocols, frequency metrics).
3. **Hybrid Detection Pipeline (`detector.py`)**:
   * **Rule Engine**: Evaluates traffic against known blacklisted malicious IPs (e.g., `203.0.113.66`) and phishing domains (e.g., `malware.test`).
   * **ML Engine**: Feeds normalized vectors into an *Isolation Forest* anomaly detector to classify unknown behavioral threats (such as DoS/DDoS volume anomalies or reconnaissance port-scanning vectors).
4. **Automated Mitigation (`mitigator.py`)**: Instantly injects high-priority kernel firewall rules (`iptables -I FORWARD`) to isolate the attacker, while generating synchronized file-system signal tokens to alert the management dashboard.
5. **Operator Visual Dashboard (`dashboard.py`)**: A real-time, Streamlit-based Security Operations Center (SOC) visualization panel showing live connected devices, active quarantine arrays, and dynamic cryptographic incident log timelines.

---

## 🚀 Installation & System Setup

Execute the following setup commands on your host Ubuntu VirtualBox environment to update repository sources and install foundational routing, compilation, and entropy utilities:

```bash
# Update repository index sources
sudo apt-get update

# Install Wi-Fi access point deployment and core routing utilities
sudo apt-get install -y hostapd dnsmasq iptables wireless-tools net-tools

# Install Haveged to maintain adequate kernel entropy and prevent cryptographic freezes
sudo apt-get install -y haveged

# Install development headers required to compile packet queue bindings
sudo apt-get install -y build-essential python3-dev libnetfilter-queue-dev

## Dependencies & Core Components
**Access Point Framework**: This project uses the core bash execution scripts from [lakinduakash/linux-wifi-hotspot](https://github.com/lakinduakash/linux-wifi-hotspot) to automate wireless interface bridging, DHCP allocation, and NAT routing.