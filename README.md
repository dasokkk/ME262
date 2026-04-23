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

- **Advanced Evasion Engine:** Every packet is unique. ME262 randomizes TTL, TCP Window Size, IP ID, and shuffles TCP Options (MSS, SackOK, WScale) to defeat signature-based detection.
- **Real-Time IDS Feedback:** Integrated with **Suricata IDS**. The scanner monitors its own detection rate in real-time.
- **AI-Powered Analyst:** Powered by **Ollama**, the built-in AI analyst reads live Suricata logs and provides strategic advice on how to adjust parameters to remain stealthy.
- **Stealth SYN Scanning:** High-performance, half-open scanning that evades kernel-level connection logging.

---

## Tech Stack
- **Packet Crafting:** Scapy (Raw L3/L4 Injection)
- **IDS Engine:** Suricata (AF_PACKET / Interface Monitoring)

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
    "use_custom_rules": true
}
```
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

## Suggested AI Config After Detection:

---

<img width="1101" height="313" alt="Ekran görüntüsü 2026-04-23 152217" src="https://github.com/user-attachments/assets/e9fb491d-2c93-45ff-9158-c11b1bc39aed" />

---

## Author
by **dasokk**
- **GitHub:** [dasokkk](https://github.com/dasokkk)

---

## ⚠️ Disclaimer
*This tool is intended for educational purposes and authorized security research only. Unauthorized scanning of networks you do not own is illegal and unethical.*

