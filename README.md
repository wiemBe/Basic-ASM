# ASM Tool - Attack Surface Management

A comprehensive Attack Surface Management tool for security engineers to discover and analyze their organization's external attack surface.

## Features

- **10 Reconnaissance Phases:**
  1. Subdomain Discovery (subfinder + httpx)
  2. Port Scanning (nmap)
  3. Technology Detection (whatweb)
  4. Vulnerability Scanning (nuclei)
  5. Screenshot Capture (gowitness)
  6. DNS Enumeration (dnsx)
  7. Directory Bruteforcing (ffuf)
  8. SSL/TLS Analysis (testssl.sh)
  9. WAF Detection (wafw00f)
  10. API Endpoint Discovery (katana, gau, waybackurls)

- **Web GUI** - Modern dashboard with real-time progress
- **Security Hardened** - Input validation, no shell injection

## Installation

### Prerequisites (Kali Linux)

```bash
# Update system
sudo apt update

# Install apt packages
sudo apt install -y nmap whatweb testssl.sh seclists golang

# Install Python dependencies
pip install -r requirements-gui.txt
pip install wafw00f

# Install Go tools
export PATH=$PATH:$HOME/go/bin
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zshrc

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/sensepost/gowitness@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest

# Update nuclei templates
nuclei -update-templates
```

## Usage

### Command Line

```bash
# Full scan
python main.py -t example.com

# Discovery only (fast)
python main.py -t example.com --discovery-only

# Skip specific modules
python main.py -t example.com --skip-vuln --skip-dirs

# Stealth mode (slower, less detectable)
python main.py -t example.com --rate-limit 3.0
```

### Web GUI

```bash
python gui.py
# Open http://localhost:5000
```

## Project Structure

```
ASM/
├── main.py              # CLI tool
├── gui.py               # Web GUI
├── requirements-gui.txt # Python dependencies
├── templates/           # GUI HTML templates
│   └── index.html
└── scanned_results/     # Scan outputs (auto-created)
    └── example.com/
        ├── subdomains.txt
        ├── live_hosts.txt
        ├── vulnerabilities.txt
        ├── api_endpoints.txt
        ├── report.md
        └── ...
```

## License

For authorized security testing only. Always obtain proper authorization before scanning.
