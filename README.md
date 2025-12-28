# ASM Tool - Attack Surface Management

A comprehensive Attack Surface Management tool for security engineers to discover and analyze their organization's external attack surface.

## Features

- **13 Reconnaissance Phases:**
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
  11. Secret Scanning (trufflehog + regex patterns)
  12. HTTP Parameter Discovery (arjun)
  13. Link/Endpoint Extraction (xnLinkFinder)

- **Web GUI** - Modern dashboard with real-time progress and live logs
- **Security Hardened** - Input validation, no shell injection
- **Auto Tool Detection** - Finds tools in ~/go/bin even without PATH configured
- **Smart Deduplication** - Uses anew for efficient result deduplication

## Installation

### Prerequisites (Kali Linux)

```bash
# Update system
sudo apt update

# Install apt packages
sudo apt install -y nmap whatweb testssl.sh seclists golang

# Install Python dependencies
pip install -r requirements.txt

# Add Go bin to PATH
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc  # or ~/.zshrc for zsh
source ~/.bashrc

# Install Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/sensepost/gowitness@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/tomnomnom/anew@latest
go install -v github.com/trufflesecurity/trufflehog/v3@latest

# Install Python-based tools
pip install arjun xnLinkFinder

# Update nuclei templates
nuclei -update-templates
```

### Note on Tool Detection

The tool automatically checks `~/go/bin`, `/root/go/bin`, and other common locations for Go-based tools, so they will work even if your PATH isn't updated. However, adding to PATH is still recommended for CLI usage.

## Usage

### Command Line

```bash
# Full scan (all 13 phases)
python main.py -t example.com

# Discovery only (fast)
python main.py -t example.com --discovery-only

# Skip specific modules
python main.py -t example.com --skip-vuln --skip-dirs

# Skip new modules
python main.py -t example.com --skip-secrets --skip-params --skip-linkfinder

# Stealth mode (slower, less detectable)
python main.py -t example.com --rate-limit 3.0

# Scan IP address instead of domain
python main.py -t 192.168.1.1 --is-ip
```

### Web GUI

```bash
python gui.py
# Open http://localhost:5000
```

The GUI provides:
- Real-time progress tracking
- Live log streaming from all scan modules
- Tool status indicators (green = installed, red = missing)
- Previous scan results browser
- Configurable scan options

## Project Structure

```
ASM/
├── main.py              # CLI tool with 13 reconnaissance modules
├── gui.py               # Flask web GUI with Socket.IO
├── requirements.txt     # Python dependencies
├── templates/           # GUI HTML templates
│   └── index.html
└── scanned_results/     # Scan outputs (auto-created)
    └── example.com/
        ├── subdomains.txt
        ├── live_hosts.txt
        ├── vulnerabilities.txt
        ├── api_endpoints.txt
        ├── secrets_found.json
        ├── discovered_params.json
        ├── extracted_links.txt
        ├── report.md
        └── ...
```

## Required Tools

| Tool | Purpose | Install |
|------|---------|---------|
| subfinder | Subdomain enumeration | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| httpx | HTTP probing | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| nmap | Port scanning | `apt install nmap` |
| whatweb | Technology detection | `apt install whatweb` |
| nuclei | Vulnerability scanning | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| gowitness | Screenshots | `go install github.com/sensepost/gowitness@latest` |
| dnsx | DNS enumeration | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| ffuf | Directory bruteforce | `go install github.com/ffuf/ffuf/v2@latest` |
| testssl.sh | SSL/TLS analysis | `apt install testssl.sh` |
| wafw00f | WAF detection | `pip install wafw00f` |
| katana | Web crawling | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| gau | URL fetching | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| waybackurls | Archive URLs | `go install github.com/tomnomnom/waybackurls@latest` |
| trufflehog | Secret scanning | `go install github.com/trufflesecurity/trufflehog/v3@latest` |
| arjun | Parameter discovery | `pip install arjun` |
| xnLinkFinder | Link extraction | `pip install xnLinkFinder` |
| anew | Deduplication | `go install github.com/tomnomnom/anew@latest` |

## CLI Options

```
Target Options:
  -t, --target          Target domain (e.g., example.com)

Module Control:
  --discovery-only      Run only subdomain discovery
  --skip-ports          Skip port scanning
  --skip-tech           Skip technology detection
  --skip-vuln           Skip vulnerability scanning
  --skip-screenshots    Skip screenshot capture
  --skip-dns            Skip DNS enumeration
  --skip-dirs           Skip directory bruteforcing
  --skip-ssl            Skip SSL/TLS analysis
  --skip-waf            Skip WAF detection
  --skip-api            Skip API endpoint discovery
  --skip-secrets        Skip secret scanning (TruffleHog)
  --skip-params         Skip parameter discovery (Arjun)
  --skip-linkfinder     Skip link extraction (xnLinkFinder)

Configuration:
  --top-ports N         Number of ports to scan (default: 1000)
  --vuln-severity       Nuclei severity filter (default: medium,high,critical)
  --rate-limit N        Delay between requests in seconds (default: 1.0)
  --crawl-depth N       Katana crawl depth (default: 3)
  --arjun-threads N     Arjun thread count (default: 10)
  --linkfinder-depth N  xnLinkFinder depth (default: 2)
  -v, --verbose         Enable debug output
```

## License

For authorized security testing only. Always obtain proper authorization before scanning.
