<div align="center">

# 🔍 pcap-analyst

**AI-powered network packet analyzer — detects threats and generates plain-English security reports**

![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=flat&logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-Packet%20Analysis-4CAF50?style=flat)
![Claude](https://img.shields.io/badge/Claude-AI%20Reports-FF6B35?style=flat)
![Security](https://img.shields.io/badge/Domain-Network%20Security-red?style=flat)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)

*Feed it a `.pcap` file. Get back a security report written by an AI analyst.*

</div>

---

## 📋 Overview

**pcap-analyst** bridges the gap between raw packet captures and actionable security insights. Wireshark shows you everything but explains nothing — this tool parses your capture, runs security heuristics, and sends the findings to Claude to produce a structured, human-readable threat report.

```
.pcap file  →  Scapy parser  →  Security detections  →  Claude API  →  Markdown report
```

---

## ✨ Detections

| Detection | Logic |
|---|---|
| 🔴 **Port Scan** | Single source IP contacting more than `N` unique destination ports |
| 🟠 **ARP Spoofing** | Same IP address claimed by multiple MAC addresses |
| 🟡 **DNS Tunneling** | Abnormally long DNS queries or unusually high DNS query volume per host |

All thresholds are configurable in `config.py`.

---

## 🚀 Getting Started

**1 — Clone the repo**
```bash
git clone https://github.com/yourusername/pcap-analyst.git
cd pcap-analyst
```

**2 — Install dependencies**
```bash
pip install scapy anthropic python-dotenv
```

**3 — Add your API key**

Create a `.env` file at the root:
```
ANTHROPIC_API_KEY=your_key_here
```
Get a key at [console.anthropic.com](https://console.anthropic.com)

**4 — Run it**
```bash
python analyzer.py --file samples/your_capture.pcap
```

The report prints to terminal and saves as a `.md` file in `reports/`.

---

## 📁 Project Structure

```
pcap-analyst/
├── analyzer.py       # CLI entry point (argparse)
├── parser.py         # Scapy pcap parsing — extracts IPs, ports, protocols, DNS
├── detector.py       # Security heuristics — port scan, ARP spoof, DNS tunneling
├── reporter.py       # Claude API integration — generates markdown report
├── config.py         # Centralized thresholds and settings
├── examples/
│   └── sample_report.md    # Example output from a real malicious capture
├── samples/          # Put your .pcap files here (gitignored)
└── reports/          # Generated reports saved here (gitignored)
```

---

## 📊 Example Output

The following report was generated from a real traffic analysis exercise pcap — `2026-02-28-traffic-analysis-exercise.pcap` sourced from [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net).

> See the full report in [`examples/sample_report.md`](./examples/sample_report.md)

**Excerpt:**

```
## Executive Summary
Two hosts on the internal network (10.2.28.2 and 10.2.28.88) exhibited
suspicious scanning behavior.

### Port Scan from 10.2.28.2 — Severity: HIGH
Host contacted 379 unique ports, indicating aggressive network reconnaissance.
IMMEDIATE: Isolate 10.2.28.2 and investigate for compromise indicators.

### DNS Alerts from 10.2.28.88 — Severity: LOW (False Positive)
Queries match legitimate Active Directory SRV record patterns (_ldap._tcp).
No immediate action required — adjust thresholds to whitelist AD traffic.
```

---

## ⚙️ Configuration

Edit `config.py` to tune detection sensitivity:

```python
PORTSCAN_THRESHOLD = 15     # unique ports before flagging a scan
DNSQ_THRESHOLD = 15         # DNS queries per host before flagging
DNS_LENGTH_THRESHOLD = 50   # query length before flagging tunneling
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Packet parsing | Scapy |
| AI report generation | Claude API (Anthropic) |
| CLI | argparse |
| Config management | python-dotenv |
| Output format | Markdown |

---

## ⚠️ Disclaimer

This tool is intended for **educational and authorized security testing only**. Only analyze traffic you own or have explicit permission to inspect.

---

## 📈 Possible Improvements

- [ ] ICMP flood detection
- [ ] TLS/SSL anomaly detection
- [ ] HTML report output option
- [ ] Batch processing multiple pcap files
- [ ] Severity scoring system with visual summary

---

<div align="center">

Built to learn — network security meets AI tooling.

</div>
