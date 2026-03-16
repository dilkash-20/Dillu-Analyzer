# Dillu-Analyzer
🛡️ Dillu Analyzer — A web-based universal malware scanner built with Python, Flask &amp; 317 YARA rules. Detects RATs, ransomware, exploits, and Android APK threats
----------------------------------------------------------------------------------------------------------------------------------------------------------------------

# 🛡️ Dillu Analyzer — Universal Malware Scanner

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-black?style=for-the-badge&logo=flask)
![YARA](https://img.shields.io/badge/YARA-317%20Rules-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey?style=for-the-badge)

**A powerful, web-based malware scanner that detects threats across every major file type — built with Python, Flask, and 317 YARA rules.**

[Features](#-features) • [Demo](#-screenshots) • [Installation](#-installation) • [Usage](#-usage) • [File Types](#-supported-file-types) • [YARA Rules](#-yara-rules)

</div>

---

## 👨‍💻 About

> **Created by [Dilkash](https://github.com/dilkash-20)** with the assistance of AI (Claude by Anthropic).
>
> This project was built as a learning and practical cybersecurity tool, combining real-world YARA malware detection rules, deep file analysis, and a modern dark-themed web interface — all in a self-contained Python application.

---

## ✨ Features

- 🔍 **317 YARA detection rules** covering malware families, exploits, RATs, ransomware, and more
- 🗂️ **Universal file type support** — PDFs, EXE/DLL, Office documents, APKs, archives, scripts, images, and more
- 🔐 **VirusTotal integration** — hash lookup and file upload for cross-reference
- 📊 **Risk scoring** — 0–100 CRITICAL / HIGH / MEDIUM / LOW scoring engine
- ⚡ **Fallback pattern scanning** — works even without `yara-python` installed
- 🌐 **Web UI** — dark cyberpunk-themed browser interface
- 📄 **JSON forensic reports** — downloadable full scan reports
- 🔒 **Auto file cleanup** — uploaded files deleted after 1 hour

---

## 🖥️ Screenshots

```
┌─────────────────────────────────────────────────────┐
│  🛡️  Dillu Analyzer Universal Malware Scanner      │
│  ─────────────────────────────────────────────────  │
│  Drop file or click to upload                       │
│                                                     │
│  [  SCAN FILE  ]   VT API Key: [____________]       │
│                                                     │
│  ● CRITICAL  Score: 95/100                          │
│  ─────────────────────────────────────────────────  │
│  YARA Matches (7):                                  │
│    🚨 SpyNote_RAT_Android    [HIGH] RAT             │
│    🚨 Android_RAT_Screen     [HIGH] RAT             │
│    🚨 Android_DeviceAdmin    [HIGH] Persistence     │
│    ...                                               │
│                                                      │
│  APK Permissions (20 dangerous):                     │
│    • android.permission.READ_SMS                     │
│    • android.permission.BIND_DEVICE_ADMIN            │
│    • android.permission.RECORD_AUDIO                 │
│    ...                                               │
└─────────────────────────────────────────────────────┘
```

---

## 📦 Project Structure

```
dillu-analyzer/
├── app/
│   ├── app.py                  # Flask API server
│   ├── utils/
│   │   ├── file_analyzer.py    # Core analysis engine
│   │   └── virustotal.py       # VirusTotal API client
│   ├── yara_rules/
│   │   └── universal_malware.yar   # 317 YARA detection rules
│   ├── templates/
│   │   └── index.html          # Web UI
│   ├── static/
│   │   ├── css/style.css       # Cyberpunk dark theme
│   │   └── js/scanner.js       # Frontend scan logic
│   └── uploads/                # Temp storage (auto-deleted)
├── requirements.txt
├── run.sh
└── README.md
```

---

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- pip
- (Optional) `libyara` for full YARA engine support

### Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/dilkash-20/dillu-analyzer.git
cd dillu-analyzer

# 2. Run the setup script (creates venv, installs deps, starts server)
chmod +x run.sh
./run.sh
```

Then open your browser at **http://localhost:5000**

---

### Manual Setup

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate         # Windows

# Install dependencies
pip install -r requirements.txt

# Install YARA engine (recommended for full rule scanning)
# Linux — install system dependency first:
sudo apt install libssl-dev libmagic-dev build-essential
pip install yara-python

# Start the scanner
cd app
python3 app.py
```

> **Note:** If `yara-python` fails to install, the scanner automatically falls back to built-in pattern matching. Detection still works, but with fewer rules.

---

### VirusTotal Integration (Optional)

```bash
# Set your VT API key as environment variable
export VIRUSTOTAL_API_KEY="your_api_key_here"

# Or enter it in the web UI before scanning
```

Get a free API key at [virustotal.com](https://www.virustotal.com)

---

## 🗂️ Supported File Types

| Category | Extensions |
|----------|-----------|
| **Android APK** | `.apk` |
| **Windows PE** | `.exe` `.dll` `.sys` |
| **Linux/macOS** | `.elf` `.so` `.dmg` |
| **PDF** | `.pdf` |
| **Office Documents** | `.doc` `.docx` `.xls` `.xlsx` `.ppt` `.pptx` `.rtf` |
| **Archives** | `.zip` `.rar` `.7z` `.tar` `.gz` `.bz2` `.jar` |
| **Scripts** | `.py` `.js` `.vbs` `.ps1` `.bat` `.cmd` `.sh` `.php` `.rb` `.pl` |
| **Images** | `.png` `.jpg` `.jpeg` `.gif` `.svg` `.tif` `.bmp` |
| **Web / Data** | `.html` `.xml` `.json` `.csv` `.txt` `.log` |
| **Other** | `.iso` `.img` `.lnk` `.eml` `.msg` |

---

## 🔍 YARA Rules

The scanner ships with **317 YARA rules** across these categories:

| Category | Rules | Description |
|----------|-------|-------------|
| Android / APK | 30+ | SpyNote RAT, Dendroid, Metasploit payloads, banking trojans |
| Anti-Debug / Anti-VM | 40+ | Debugger checks, VM detection, sandbox evasion |
| Capabilities | 50+ | Process injection, keyloggers, RAT features, credential theft |
| Crypto Signatures | 60+ | AES, RSA, DES, SHA, MD5 constant detection |
| CVE Exploits | 20+ | CVE-2017-11882, CVE-2018-4878, CVE-2016-5195, and more |
| PDF Malware | 10 | JavaScript, shellcode, obfuscation, auto-launch |
| Windows PE | 10 | Ransomware, packers, process injection |
| Office Macros | 5 | AutoExec, DDE attacks, obfuscated VBA |
| Scripts | 5 | Encoded PowerShell, droppers, persistence |
| Generic | 5 | NOP sleds, TOR indicators, crypto wallets |

### SpyNote RAT Detection

Dillu Analyzer includes a custom rule specifically built to detect SpyNote Android RAT, including obfuscated variants that encode the package name in base64:

```
Package: cmf0.c3b5bm90zq.patch
         └── c3b5bm90zq = base64("spynote")
```

Detection checks:
- ✅ APK magic bytes + `classes.dex` presence
- ✅ Obfuscated package name (`c3b5bm90zq`) or C2 endpoint (`/exit/chat/`)
- ✅ Screen capture, network socket, and surveillance capabilities
- ✅ UTF-16LE dangerous permissions (READ_SMS, BIND_DEVICE_ADMIN, RECORD_AUDIO, etc.)

---

## 🧠 How It Works

```
Upload File
     │
     ▼
┌─────────────────┐
│  File Type      │  Magic bytes + extension detection
│  Detection      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  ZIP Extraction │  For APK/JAR/ZIP: decompress all entries
│  (for YARA)     │  so YARA can scan uncompressed content
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  YARA Scan      │  317 rules against combined raw+extracted bytes
│                 │  Falls back to pattern scan if yara-python missing
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Type-Specific  │  PDF / APK / PE / Office / Script / Image
│  Deep Analysis  │  analyzers extract indicators
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  VirusTotal     │  Hash lookup → file upload (if no match)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Risk Score     │  0–100  CRITICAL / HIGH / MEDIUM / LOW
│  + JSON Report  │
└─────────────────┘
```

---

## 🔌 API

The scanner exposes a simple REST API:

### Scan a file

```http
POST /api/scan
Content-Type: multipart/form-data

file=<binary>
vt_api_key=<optional>
```

**Response:**
```json
{
  "scan_id": "uuid",
  "risk": {
    "score": 95,
    "level": "CRITICAL",
    "color": "#ff2d55"
  },
  "yara_results": {
    "rule_count": 7,
    "matches": [
      {
        "rule": "SpyNote_RAT_Android",
        "severity": "HIGH",
        "category": "RAT",
        "description": "Detects SpyNote Android RAT..."
      }
    ]
  },
  "type_analysis": {
    "analyzer": "Android APK",
    "apk_analysis": {
      "dangerous_permissions": ["android.permission.READ_SMS", "..."],
      "suspicious_indicators": ["SpyNote encoded package (c3b5bm90zq)", "..."]
    }
  }
}
```

### Download report

```http
GET /api/report/<scan_id>
```

Returns the full JSON forensic report as a downloadable file.

---

## ⚙️ Configuration

| Setting | Default | How to change |
|---------|---------|---------------|
| Port | `5000` | Edit `app.py` line: `app.run(port=5000)` |
| Max file size | `100MB` | Edit `app.config['MAX_CONTENT_LENGTH']` |
| File retention | `1 hour` | Edit `cleanup_old_files()` threshold |
| VirusTotal key | *(empty)* | `export VIRUSTOTAL_API_KEY="key"` |
| YARA rules path | `yara_rules/universal_malware.yar` | Edit `app.config['YARA_RULES']` |

---

## 🐛 Troubleshooting

**`yara-python` install fails:**
```bash
# Ubuntu/Debian
sudo apt install libssl-dev libmagic-dev build-essential python3-dev
pip install yara-python

# If still failing, scanner uses fallback detection automatically
```

**Port already in use:**
```bash
# Change port in app.py, or kill existing process:
lsof -ti:5000 | xargs kill
```

**APK not detected:**
- Make sure the file has `.apk` extension when uploading
- The scanner uses extension + magic bytes to route APK files to the dedicated analyzer

**YARA rules not loading:**
```bash
# Verify the rules file compiles cleanly:
python3 -c "import yara; yara.compile('app/yara_rules/universal_malware.yar'); print('OK')"
```

---

## 🔒 Security Notes

- All uploaded files are **automatically deleted after 1 hour**
- Files are stored in `uploads/` with UUID-prefixed names
- This tool is intended for **security research and malware analysis only**
- Do **not** expose this server publicly without authentication
- Never upload sensitive or personal files to any scanner you do not control

---

## 📋 Requirements

```
flask>=3.0.0
werkzeug>=3.0.0
requests>=2.31.0
yara-python>=4.3.0    # optional but recommended
```

---

## 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you'd like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/new-detection`)
3. Commit your changes (`git commit -m 'Add detection for XYZ malware'`)
4. Push to the branch (`git push origin feature/new-detection`)
5. Open a Pull Request

---

## 📜 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

The YARA rules included in this project are sourced from open community rulesets and are licensed under GNU-GPLv2 where applicable. See individual rule metadata for attribution.

---

## 🙏 Acknowledgements

- **YARA rules** — community rulesets from [naxonez](https://github.com/naxonez/yaraRules), [x0r](https://github.com/x0r), [Florian Roth](https://github.com/Neo23x0), and others
- **SpyNote analysis** — custom rule developed from reverse-engineering `client.apk`
- **Flask** — lightweight Python web framework
- **yara-python** — Python bindings for the YARA pattern matching library

---

<div align="center">

**Built by Dilkash with the help of AI 🤖**

*"Security is not a product, but a process."* — Bruce Schneier

⭐ Star this repo if you found it useful!

</div>
