# 🛡️ SCANDERE - Web Vulnerability Scanner

<div align="center">

```
███████╗ ██████╗ █████╗ ███╗   ██╗██████╗ ███████╗██████╗ ███████╗
██╔════╝██╔════╝██╔══██╗████╗  ██║██╔══██╗██╔════╝██╔══██╗██╔════╝
███████╗██║     ███████║██╔██╗ ██║██║  ██║█████╗  ██████╔╝█████╗  
╚════██║██║     ██╔══██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗██╔══╝  
███████║╚██████╗██║  ██║██║ ╚████║██████╔╝███████╗██║  ██║███████╗
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝
```

**Advanced Web Security Scanner for XSS, SQLi & Open Redirects**

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

</div>

---

## 🎯 What is SCANDERE?

A powerful, all-in-one web vulnerability scanner that detects:
- ✅ **Reflected XSS** - Parameter injection attacks
- ✅ **DOM-based XSS** - Client-side vulnerabilities  
- ✅ **Stored XSS** - Persistent injection via forms
- ✅ **SQL Injection** - Error/Boolean/Time-based
- ✅ **Open Redirects** - Unvalidated redirections

---

## 🚀 Quick Start

### Installation
```bash
# Clone repository
git clone https://github.com/yourusername/scandere.git
cd scandere

# Install dependencies
pip install -r requirements.txt

# Optional: Install ChromeDriver for DOM XSS
sudo apt-get install chromium-chromedriver  # Ubuntu/Debian
brew install chromedriver                    # macOS
```

### Basic Usage
```bash
# Simple scan
python scandere.py -t https://example.com

# Fast scan
python scandere.py -t https://example.com --fast

# With authentication
python scandere.py -t https://example.com --cookies '{"session":"abc123"}'

# Custom output
python scandere.py -t https://example.com -o reports/my_scan.html
```

---

## 📖 Command Options

| Option | Description |
|--------|-------------|
| `-t, --target` | Target URL (required) |
| `-o, --output` | Output report filename |
| `--cookies` | Auth cookies as JSON |
| `--login-url` | Login URL |
| `--credentials` | Login credentials as JSON |
| `--fast` | Use fewer payloads |
| `--no-dom` | Skip DOM XSS detection |
| `--no-stored` | Skip stored XSS detection |

---

## 💡 Examples

**Basic Scan:**
```bash
python scandere.py -t https://testphp.vulnweb.com
```

**Authenticated Scan:**
```bash
python scandere.py -t https://app.example.com \
  --cookies '{"session":"token"}' \
  -o reports/auth_scan.html
```

**Quick Scan (No Selenium):**
```bash
python scandere.py -t https://example.com --no-dom --fast
```

---

## 🔐 Authentication

**Cookie-based:**
```bash
python scandere.py -t https://example.com --cookies '{"session_id":"abc123"}'
```

**Login-based:**
```bash
python scandere.py -t https://example.com \
  --login-url https://example.com/login \
  --credentials '{"username":"admin","password":"pass"}'
```

---

## 📊 Features

- 🎯 Auto endpoint & form discovery
- 🚀 Parallel multi-threaded scanning
- 🔐 Session management & authentication
- 📈 Beautiful HTML reports with evidence
- 🎨 Color-coded terminal output
- ⚡ Fast mode for quick assessments

---

## 🐛 Troubleshooting

**Selenium not found?**
```bash
pip install selenium
# OR skip DOM XSS:
python scandere.py -t https://example.com --no-dom
```

**ChromeDriver missing?**  
Install ChromeDriver (see installation) or use `--no-dom`

---

## ⚠️ Disclaimer

**For authorized testing only!** 

- ✅ Use on systems you own or have permission to test
- ❌ Do NOT use on unauthorized systems
- ❌ Do NOT use for malicious purposes

You are responsible for your actions. The developers assume no liability.

---

## 🤝 Contributing

Contributions welcome! Open issues or submit PRs.

---

## 📜 License

MIT License - See [LICENSE](LICENSE) file

---

<div align="center">

**⭐ Star this repo if you find it useful! ⭐**

Made with 🛡️ by security enthusiasts

</div>