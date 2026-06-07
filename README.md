<h1 align="center">║ ME262 - AI-Adaptive Stealth Scanner & Active IDS ║</h1>

<p align="center">
  <img src="https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54" />
  <img src="https://img.shields.io/badge/Scapy-EE0000?style=for-the-badge&logo=scapy&logoColor=white" />
  <img src="https://img.shields.io/badge/Suricata-EF3B24?style=for-the-badge&logo=suricata&logoColor=white" />
  <img src="https://img.shields.io/badge/Ollama-black?style=for-the-badge&logo=ollama&logoColor=white" />
</p>
**ME262** is a next-generation, high-performance network reconnaissance tool designed to bypass modern Intrusion Detection Systems (IDS) using AI-driven packet crafting and behavioral analysis.

---

## Features

- **Interactive Setup Wizard:** Effortlessly configure targets, profiles, evasion techniques, and AI models through a guided console UI.
- **Advanced Evasion Engine:** Every packet is unique. ME262 randomizes TTL, TCP Window Size, IP ID, and shuffles TCP Options (MSS, SackOK, WScale) to defeat signature-based detection.
- **Full Evasion Suite:** App-Layer Spoofing (HTTP/TLS/DNS), Full Connect scans, real SSL/TLS handshakes, Proxy Routing, IP Fragmentation (MTU), **decoy scanning**, **source IP/MAC spoofing**, **custom TTL**, **IP options**, and **bad TCP checksums**.
- **Closed AI Control Loop:** The AI analyst can now actually enact what it recommends — it adjusts the full evasion surface (rate, timing, fragmentation, app-spoofing, proxy, decoys, TTL, checksums …), all validated before being applied.
- **Adaptive Detection-Rate Controller:** Tracks the live detection rate (alerts ÷ probes over a sliding window) and, when it crosses a configurable threshold, automatically walks an escalating ladder of stealth adjustments — a real **No-AI fallback** that adapts instead of just pausing.
- **Auto-Evade Mode:** `--auto-evade` lets the scanner converge on a quiet configuration on its own, with no operator prompts.
- **Pluggable IDS Backends:** Run against **Suricata** behind a single interface — with **Snort** and **Zeek** available as *experimental* backends. Suricata is the fully validated default; Snort/Zeek are implemented but require extra configuration and have not yet been validated end-to-end (see *IDS Evaluation & Evasion*).
- **Evasion Memory:** Persists which parameter sets triggered which signatures across runs and feeds that history back to the AI analyst.
- **Recon Depth:** Optional banner/version grabbing on open ports.
- **Multi-Target & CIDR/IPv6:** Scan a single host, a comma-separated list, or a whole `10.0.0.0/24` range (IPv4 and IPv6).
- **Session Reporting:** Export JSON/CSV results plus an after-action evasion debrief with `--export`.
- **AI-Powered Analyst:** Powered by **Ollama**, the built-in AI analyst reads live IDS logs and provides strategic advice on how to adjust parameters to remain stealthy.
- **Stealth SYN Scanning:** High-performance, half-open scanning that evades kernel-level connection logging.
- **Tunable Scan Profiles:** Flip the entire timing/port/timeout posture with a single flag — `-f` (aggressive), `-n` (normal), or `-s` (stealth) — or override the scan rate (`-r`) and per-probe timeout (`--timeout`) directly.
- **Flexible Port Selection:** Pick how ports are chosen with `-p` — `top` well-known ports, a `random` sample, a `sequential` 1–1024 sweep, or a `weighted` mix of top + random high ports.
- **Operational Controls:** Quiet output that shows only open ports and IDS alerts (`-q`), explicit sniff/send interface selection (`-I`), and independent toggles to run without the AI analyst (`--disable-ai`) or without IDS monitoring (`--disable-ids`).

---

## Tech Stack
- **Packet Crafting:** Scapy (Raw L3/L4 Injection)
- **IDS Engines:** Suricata (validated) / Snort / Zeek (experimental) — Interface Monitoring
- **AI Analyst:** Ollama (local LLM HTTP API)

---

## Installation

### 1. Prerequisites
Ensure you have the following installed on your Kali Linux (or any Debian-based system):
```bash
sudo apt update && sudo apt install suricata python3-pip -y
curl -fsSL https://ollama.com/install.sh | sh
```

### 2. Clone and Setup
```bash
git clone https://github.com/dasokkk/ME262.git
cd ME262
pip install -r requirements.txt
```

### 3. Usage
```bash
sudo python src/main.py
```
*Note: ME262 requires root privileges to craft raw packets and interface with Suricata.*

---

## AI Configuration
By default, **ME262** is configured to use the `f0rc3ps/nu11secur1tyAI:latest` model, which is specifically fine-tuned for cybersecurity tasks. 

If you wish to use a different model (e.g., `llama3`, `mistral`, or `gemma`), you can easily change it in the `config.json` file:
```json
"ai": {
    "model": "your-preferred-model",
    "base_url": "http://localhost:11434"
}
```

---

## IDS Evaluation & Evasion
ME262 includes a "Paranoid Mode" in `config.json` that enables custom high-sensitivity rules. This allows researchers to test their scanning techniques against expert-level IDS configurations.

```json
"ids": {
    "engine": "suricata",
    "use_custom_rules": true,
    "time_window": 10.0,
    "detection_threshold": 0.45,
    "snort_config": null,
    "zeek_scripts": []
}
```

- **`engine`** — choose `suricata`, `snort`, or `zeek` (or pass `--ids-engine`). **Suricata** is the validated default. **Snort** and **Zeek** are *experimental*: Snort needs a config (`snort_config`) to load any rules, and Zeek needs a scan-detection script (`zeek_scripts`) or it will not raise any notices. Neither has been validated end-to-end yet.
- **`time_window` / `detection_threshold`** — drive the adaptive controller. When `alerts ÷ probes` over the window exceeds the threshold, the No-AI fallback (and `--auto-evade`) escalate evasion automatically.
---

## Screenshots:

<img width="989" height="776" alt="Ekran görüntüsü 2026-04-23 151736" src="https://github.com/user-attachments/assets/2e290955-06fc-4694-a760-fbd13ddc349b" />

---

<img width="1104" height="553" alt="Ekran görüntüsü 2026-04-23 151811" src="https://github.com/user-attachments/assets/49cb945d-0cb2-43d3-be2b-5848089ed9c6" />

---

<img width="1103" height="609" alt="Ekran görüntüsü 2026-04-23 151851" src="https://github.com/user-attachments/assets/3ecc15ca-36bc-428a-b300-8b6a51999d9b" />

---

<img width="1094" height="565" alt="Ekran görüntüsü 2026-04-23 151913" src="https://github.com/user-attachments/assets/c4f04ec1-e380-4b14-bc60-ad786f1b6c96" />

---

<img width="1045" height="744" alt="Ekran görüntüsü 2026-04-23 151930" src="https://github.com/user-attachments/assets/11d2d0fc-acd5-42fb-9d07-84c7235fe881" />

---

<img width="568" height="309" alt="image" src="https://github.com/user-attachments/assets/790e5356-3a0b-4925-a06f-aa7bd8b4c006" />

---

## Suggested AI Config After Detection:

---

<img width="1101" height="313" alt="Ekran görüntüsü 2026-04-23 152217" src="https://github.com/user-attachments/assets/e9fb491d-2c93-45ff-9158-c11b1bc39aed" />

---

## Author
by **dasokk**
- **GitHub:** [dasokkk](https://github.com/dasokkk)

## Supported Evasion & Recon Options

| Approach | Argument |
| :--- | :--- |
| Hide a scan with decoys | `-D DECOY_IP1,DECOY_IP2,ME` |
| Hide a scan with random decoys | `-D RND,RND,ME` |
| Route connections through proxies | `--proxy socks5://127.0.0.1:9050` |
| Spoof source MAC address | `--spoof-mac MAC_ADDRESS` |
| Spoof source IP address | `-S IP_ADDRESS` |
| Use a specific source port number | `-g PORT_NUM` |
| Set TTL | `--ttl VALUE` |
| Set IP Options | `--ip-options HEX_STRING` (e.g. `\x01\x07`) |
| Use a bad TCP checksum | `--badsum` |
| Spoof app-layer payloads | `--spoof-app` |
| Full TCP handshake (connect) | `--full-connect` |
| Real SSL/TLS handshake | `--ssl-scan` |
| Fragment packets | `--mtu 16` |
| Grab banners / versions | `--banner-grab` |
| Auto-adapt on detection | `--auto-evade` |
| Choose IDS backend | `--ids-engine {suricata,snort,zeek}` *(snort/zeek experimental)* |
| Choose a scan profile | `-f` (aggressive) · `-n` (normal) · `-s` (stealth) |
| Select a port strategy | `-p {top,random,sequential,weighted}` |
| Set the scan rate (probes/sec) | `-r RATE` |
| Set the per-probe timeout | `--timeout SECONDS` |
| Pick the sniff/send interface | `-I IFACE` |
| Quiet output (open ports + alerts only) | `-q` |
| Export reports | `--export PREFIX` |

---

> [!NOTE]
> **IP Options:** One of the IP header fields is the IP Options field. ME262 lets you control it with `--ip-options HEX_STRING`, where each byte is written as `\xHH` (two hexadecimal digits per byte).

---

## ⚠️ Disclaimer
*This tool is intended for educational purposes and authorized security research only. Unauthorized scanning of networks you do not own is illegal and unethical.*

