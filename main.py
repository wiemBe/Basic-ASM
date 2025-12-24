import subprocess
import os
import argparse
import sys
import re
import shutil
import logging
import time
import json
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging for audit trail
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Console handler (always active)
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(console_handler)

# Configuration constants
COMMAND_TIMEOUT = 300  # 5 minutes max per command
OUTPUT_DIR = "scanned_results"
RATE_LIMIT_DELAY = 1.0  # Seconds between requests (adjustable)


class RateLimiter:
    """Simple rate limiter to avoid overwhelming targets or getting blocked."""
    
    def __init__(self, delay=RATE_LIMIT_DELAY):
        self.delay = delay
        self.last_request = 0
    
    def wait(self):
        """Wait if necessary to respect rate limit."""
        elapsed = time.time() - self.last_request
        if elapsed < self.delay:
            sleep_time = self.delay - elapsed
            logger.debug(f"Rate limiting: sleeping {sleep_time:.2f}s")
            time.sleep(sleep_time)
        self.last_request = time.time()
    
    def set_delay(self, delay):
        """Update the delay between requests."""
        self.delay = delay
        logger.info(f"Rate limit set to {delay}s between requests")


# Global rate limiter instance
rate_limiter = RateLimiter()

def is_valid_ip(ip):
    """
    Check if string is a valid IPv4 or IPv6 address.
    """
    # IPv4 pattern
    ipv4_pattern = re.compile(
        r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    # IPv6 pattern (simplified)
    ipv6_pattern = re.compile(
        r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|'
        r'^([0-9a-fA-F]{1,4}:){1,7}:$|'
        r'^::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$'
    )
    return bool(ipv4_pattern.match(ip) or ipv6_pattern.match(ip))


def validate_target(target, is_ip=False):
    """
    Validate target (domain or IP) format to prevent command injection.
    Returns tuple: (validated_target, is_ip_address)
    """
    # Additional security checks
    dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '\n', '\r', ' ']
    if any(char in target for char in dangerous_chars):
        raise ValueError(f"Target contains forbidden characters: {target}")
    
    if is_ip:
        # Validate IP address
        if not is_valid_ip(target):
            raise ValueError(f"Invalid IP address format: {target}")
        return target, True
    else:
        # Validate domain
        domain_pattern = re.compile(
            r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)'  # Labels (no leading/trailing hyphens)
            r'(\.[A-Za-z0-9-]{1,63})*'          # Additional labels
            r'\.[A-Za-z]{2,}$'                   # TLD
        )
        if not domain_pattern.match(target):
            raise ValueError(f"Invalid domain format: {target}")
        return target, False


def validate_domain(domain):
    """
    Validate domain format to prevent command injection.
    Only allows valid domain characters: alphanumeric, hyphens, and dots.
    Legacy function - use validate_target() for new code.
    """
    target, _ = validate_target(domain, is_ip=False)
    return target

def check_tool_exists(tool_name):
    """Verify required tools are installed before running."""
    # First check if tool is in PATH
    if shutil.which(tool_name) is not None:
        return True
    
    # Check common binary locations (in case PATH not updated)
    common_paths = [
        # Go binaries
        os.path.expanduser("~/go/bin"),
        "/root/go/bin",
        "/usr/local/go/bin",
        os.path.expanduser("~/.local/bin"),
        # testssl.sh common locations
        "/usr/bin",
        "/usr/local/bin",
        "/opt/testssl.sh",
        os.path.expanduser("~/testssl.sh"),
        os.path.expanduser("~/tools/testssl.sh"),
    ]
    
    for bin_path in common_paths:
        tool_path = os.path.join(bin_path, tool_name)
        if os.path.isfile(tool_path) and os.access(tool_path, os.X_OK):
            return True
    
    logger.error(f"Required tool '{tool_name}' not found in PATH")
    return False

def get_tool_path(tool_name):
    """Get the full path to a tool, checking common locations."""
    # First check if tool is in PATH
    path = shutil.which(tool_name)
    if path:
        return path
    
    # Check common binary locations
    common_paths = [
        # Go binaries
        os.path.expanduser("~/go/bin"),
        "/root/go/bin",
        "/usr/local/go/bin",
        os.path.expanduser("~/.local/bin"),
        # testssl.sh common locations
        "/usr/bin",
        "/usr/local/bin",
        "/opt/testssl.sh",
        os.path.expanduser("~/testssl.sh"),
        os.path.expanduser("~/tools/testssl.sh"),
    ]
    
    for bin_path in common_paths:
        tool_path = os.path.join(bin_path, tool_name)
        if os.path.isfile(tool_path) and os.access(tool_path, os.X_OK):
            return tool_path
    
    # Return original name as fallback (will fail if not in PATH)
    return tool_name

def run_command(command_args, input_file=None, output_file=None, timeout=COMMAND_TIMEOUT):
    """
    Secure command execution without shell=True.
    Uses argument list to prevent command injection.
    """
    try:
        stdin_data = None
        if input_file and os.path.exists(input_file):
            with open(input_file, 'r') as f:
                stdin_data = f.read()
        
        # Resolve the tool path for the first argument (the command)
        resolved_args = command_args.copy()
        if resolved_args:
            resolved_args[0] = get_tool_path(resolved_args[0])
        
        logger.info(f"Executing: {' '.join(resolved_args)}")
        
        result = subprocess.run(
            resolved_args,
            input=stdin_data,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False  # Handle errors manually for better logging
        )
        
        if result.returncode != 0:
            logger.warning(f"Command returned non-zero exit code: {result.returncode}")
            if result.stderr:
                logger.debug(f"stderr: {result.stderr}")
        
        # Write output to file if specified
        if output_file and result.stdout:
            with open(output_file, 'w') as f:
                f.write(result.stdout)
        
        return result.stdout
        
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out after {timeout} seconds")
        return None
    except FileNotFoundError:
        logger.error(f"Command not found: {command_args[0]}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error executing command: {e}")
        return None

def count_lines_safely(filepath):
    """Safely count lines in a file with proper resource management."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return sum(1 for _ in f)
    except (IOError, OSError) as e:
        logger.error(f"Error reading file {filepath}: {e}")
        return 0

def setup_output_directory(target_domain):
    """Create a dedicated output directory for the scan results."""
    safe_domain = re.sub(r'[^\w\-.]', '_', target_domain)
    output_path = Path(OUTPUT_DIR) / safe_domain
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Setup file logging in the output directory
    log_file = output_path / "scan.log"
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(file_handler)
    
    return output_path

def module_discovery(target_domain):
    """
    Phase 1: Subdomain Discovery
    Finds subdomains and checks for live web servers.
    """
    logger.info(f"Starting Phase 1: Subdomain Discovery for {target_domain}")
    
    # Validate domain before proceeding
    try:
        target_domain = validate_domain(target_domain)
    except ValueError as e:
        logger.error(f"Domain validation failed: {e}")
        return None
    
    # Check required tools exist (httpx can be httpx-toolkit or httpx)
    if not check_tool_exists('subfinder'):
        logger.error("Missing required tool: subfinder. Please install it first.")
        return None
    
    # Find httpx command (different names on different systems)
    httpx_cmd = None
    for cmd in ['httpx-toolkit', 'httpx']:
        if check_tool_exists(cmd):
            httpx_cmd = cmd
            break
    
    if not httpx_cmd:
        logger.error("Missing required tool: httpx. Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
        return None
    
    # Setup output directory
    output_dir = setup_output_directory(target_domain)
    subs_file = output_dir / "subdomains.txt"
    alive_file = output_dir / "live_hosts.txt"
    
    # 1. Run Subfinder (secure - no shell injection possible)
    logger.info("Running Subfinder...")
    subfinder_args = ['subfinder', '-d', target_domain, '-silent']
    run_command(subfinder_args, output_file=str(subs_file))

    # Check if subfinder found anything
    if subs_file.exists() and subs_file.stat().st_size > 0:
        count = count_lines_safely(subs_file)
        logger.info(f"Found {count} subdomains")
    else:
        logger.warning("No subdomains found or tool failed")
        return output_dir

    # 2. Run HTTPX (Live Host Check)
    logger.info("Running HTTPX to check for live web servers...")
    httpx_args = [httpx_cmd, '-silent', '-sc', '-title']
    run_command(httpx_args, input_file=str(subs_file), output_file=str(alive_file))

    if alive_file.exists() and alive_file.stat().st_size > 0:
        live_count = count_lines_safely(alive_file)
        logger.info(f"{live_count} live hosts saved to: {alive_file}")
    else:
        logger.warning("No live hosts found")
    
    logger.info(f"Results saved in: {output_dir}")
    return output_dir


def module_port_scan(output_dir, top_ports=1000):
    """
    Phase 2: Port Scanning
    Scans live hosts for open ports using nmap.
    """
    logger.info("Starting Phase 2: Port Scanning")
    
    alive_file = output_dir / "live_hosts.txt"
    ports_file = output_dir / "ports.txt"
    ports_json = output_dir / "ports.json"
    
    if not alive_file.exists() or alive_file.stat().st_size == 0:
        logger.warning("No live hosts file found. Skipping port scan.")
        return False
    
    if not check_tool_exists('nmap'):
        logger.error("nmap not found. Please install it: apt install nmap")
        return False
    
    # Extract just the hostnames/IPs from httpx output (first column)
    hosts = []
    with open(alive_file, 'r') as f:
        for line in f:
            # httpx output format: URL [STATUS] [TITLE]
            url = line.split()[0] if line.strip() else None
            if url:
                # Extract hostname from URL
                host = re.sub(r'^https?://', '', url).split('/')[0].split(':')[0]
                if host not in hosts:
                    hosts.append(host)
    
    if not hosts:
        logger.warning("No valid hosts extracted for port scanning")
        return False
    
    # Write hosts to temp file for nmap
    hosts_file = output_dir / "hosts_for_scan.txt"
    with open(hosts_file, 'w') as f:
        f.write('\n'.join(hosts))
    
    logger.info(f"Scanning {len(hosts)} hosts for top {top_ports} ports...")
    rate_limiter.wait()
    
    # Run nmap with service detection
    # -sV: Version detection, -sC: Default scripts, --top-ports: Most common ports
    nmap_args = [
        'nmap',
        '-sV',                          # Service version detection
        '-sC',                          # Default scripts
        f'--top-ports={top_ports}',     # Scan top N ports
        '-oN', str(ports_file),         # Normal output
        '-oX', str(output_dir / "ports.xml"),  # XML output for parsing
        '--open',                       # Only show open ports
        '-T3',                          # Timing template (balanced)
        '-iL', str(hosts_file)          # Input from file
    ]
    
    run_command(nmap_args, timeout=COMMAND_TIMEOUT * 2)  # Double timeout for nmap
    
    if ports_file.exists():
        logger.info(f"Port scan results saved to: {ports_file}")
        return True
    
    return False


def module_tech_detect(output_dir):
    """
    Phase 3: Technology Detection
    Identifies web technologies using whatweb.
    """
    logger.info("Starting Phase 3: Technology Detection")
    
    alive_file = output_dir / "live_hosts.txt"
    tech_file = output_dir / "technologies.txt"
    tech_json = output_dir / "technologies.json"
    
    if not alive_file.exists() or alive_file.stat().st_size == 0:
        logger.warning("No live hosts file found. Skipping tech detection.")
        return False
    
    if not check_tool_exists('whatweb'):
        logger.error("whatweb not found. Please install it: apt install whatweb")
        return False
    
    # Extract URLs from alive hosts
    urls = []
    with open(alive_file, 'r') as f:
        for line in f:
            url = line.split()[0] if line.strip() else None
            if url and url.startswith('http'):
                urls.append(url)
    
    if not urls:
        logger.warning("No valid URLs for tech detection")
        return False
    
    # Write URLs to temp file
    urls_file = output_dir / "urls_for_tech.txt"
    with open(urls_file, 'w') as f:
        f.write('\n'.join(urls))
    
    logger.info(f"Detecting technologies on {len(urls)} URLs...")
    rate_limiter.wait()
    
    # Run whatweb
    whatweb_args = [
        'whatweb',
        '--input-file', str(urls_file),
        '--log-json', str(tech_json),
        '--aggression', '1',            # Stealthy mode
        '--color', 'never',
        '--no-errors'
    ]
    
    result = run_command(whatweb_args, output_file=str(tech_file))
    
    if tech_file.exists() or tech_json.exists():
        logger.info(f"Technology detection results saved to: {tech_file}")
        return True
    
    return False


def module_vuln_scan(output_dir, severity="medium,high,critical", templates=None):
    """
    Phase 4: Vulnerability Scanning
    Runs nuclei templates against discovered hosts.
    """
    logger.info("Starting Phase 4: Vulnerability Scanning with Nuclei")
    
    alive_file = output_dir / "live_hosts.txt"
    vuln_file = output_dir / "vulnerabilities.txt"
    vuln_json = output_dir / "vulnerabilities.json"
    
    if not alive_file.exists() or alive_file.stat().st_size == 0:
        logger.warning("No live hosts file found. Skipping vulnerability scan.")
        return False
    
    if not check_tool_exists('nuclei'):
        logger.error("nuclei not found. Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        return False
    
    # Extract URLs
    urls = []
    with open(alive_file, 'r') as f:
        for line in f:
            url = line.split()[0] if line.strip() else None
            if url and url.startswith('http'):
                urls.append(url)
    
    if not urls:
        logger.warning("No valid URLs for vulnerability scanning")
        return False
    
    urls_file = output_dir / "urls_for_vuln.txt"
    with open(urls_file, 'w') as f:
        f.write('\n'.join(urls))
    
    logger.info(f"Running vulnerability scan on {len(urls)} URLs (severity: {severity})...")
    rate_limiter.wait()
    
    # Build nuclei command
    nuclei_args = [
        'nuclei',
        '-l', str(urls_file),
        '-o', str(vuln_file),
        '-jsonl', str(vuln_json),
        '-severity', severity,
        '-silent',
        '-rate-limit', '50',            # Requests per second
        '-bulk-size', '25',             # Hosts in parallel
        '-concurrency', '10'            # Template concurrency
    ]
    
    # Add specific templates if provided
    if templates:
        nuclei_args.extend(['-t', templates])
    
    run_command(nuclei_args, timeout=COMMAND_TIMEOUT * 3)  # Extended timeout
    
    if vuln_file.exists() and vuln_file.stat().st_size > 0:
        vuln_count = count_lines_safely(vuln_file)
        logger.info(f"Found {vuln_count} potential vulnerabilities!")
        logger.info(f"Results saved to: {vuln_file}")
        return True
    else:
        logger.info("No vulnerabilities found (this is good!)")
        return True


def module_screenshot(output_dir, threads=4):
    """
    Phase 5: Screenshot Capture
    Takes screenshots of live web applications using gowitness.
    """
    logger.info("Starting Phase 5: Screenshot Capture")
    
    alive_file = output_dir / "live_hosts.txt"
    screenshot_dir = output_dir / "screenshots"
    screenshot_dir.mkdir(exist_ok=True)
    
    if not alive_file.exists() or alive_file.stat().st_size == 0:
        logger.warning("No live hosts file found. Skipping screenshots.")
        return False
    
    if not check_tool_exists('gowitness'):
        logger.error("gowitness not found. Install: go install github.com/sensepost/gowitness@latest")
        return False
    
    # Extract URLs
    urls = []
    with open(alive_file, 'r') as f:
        for line in f:
            url = line.split()[0] if line.strip() else None
            if url and url.startswith('http'):
                urls.append(url)
    
    if not urls:
        logger.warning("No valid URLs for screenshots")
        return False
    
    urls_file = output_dir / "urls_for_screenshots.txt"
    with open(urls_file, 'w') as f:
        f.write('\n'.join(urls))
    
    logger.info(f"Capturing screenshots for {len(urls)} URLs...")
    rate_limiter.wait()
    
    # Run gowitness
    gowitness_args = [
        'gowitness',
        'file',
        '-f', str(urls_file),
        '-P', str(screenshot_dir),
        '--threads', str(threads),
        '--timeout', '30',
        '--delay', '2'                  # Wait for page load
    ]
    
    run_command(gowitness_args, timeout=COMMAND_TIMEOUT * 2)
    
    # Count screenshots
    screenshots = list(screenshot_dir.glob('*.png'))
    if screenshots:
        logger.info(f"Captured {len(screenshots)} screenshots in: {screenshot_dir}")
        return True
    else:
        logger.warning("No screenshots captured")
        return False


def module_dns_enum(output_dir, target_domain):
    """
    Phase 6: DNS Record Enumeration
    Enumerates DNS records for discovered subdomains using dnsx.
    """
    logger.info("Starting Phase 6: DNS Record Enumeration")
    
    subs_file = output_dir / "subdomains.txt"
    dns_file = output_dir / "dns_records.txt"
    dns_json = output_dir / "dns_records.json"
    
    if not subs_file.exists() or subs_file.stat().st_size == 0:
        logger.warning("No subdomains file found. Skipping DNS enumeration.")
        return False
    
    if not check_tool_exists('dnsx'):
        logger.error("dnsx not found. Install: go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest")
        return False
    
    logger.info("Enumerating DNS records (A, AAAA, CNAME, MX, NS, TXT, SOA)...")
    rate_limiter.wait()
    
    # Run dnsx with multiple record types
    dnsx_args = [
        'dnsx',
        '-l', str(subs_file),
        '-a', '-aaaa', '-cname', '-mx', '-ns', '-txt', '-soa',  # Record types
        '-resp',                        # Show response
        '-o', str(dns_file),
        '-json', '-jo', str(dns_json),
        '-silent',
        '-retry', '2',
        '-rate-limit', '100'            # DNS queries per second
    ]
    
    run_command(dnsx_args, timeout=COMMAND_TIMEOUT)
    
    if dns_file.exists() and dns_file.stat().st_size > 0:
        record_count = count_lines_safely(dns_file)
        logger.info(f"Found {record_count} DNS records")
        logger.info(f"DNS records saved to: {dns_file}")
        return True
    else:
        logger.warning("No DNS records found")
        return False


def module_dir_bruteforce(output_dir, wordlist=None, threads=50, extensions="php,asp,aspx,jsp,html,js"):
    """
    Phase 7: Directory/File Bruteforcing
    Discovers hidden directories and files using ffuf.
    """
    logger.info("Starting Phase 7: Directory Bruteforcing")
    
    alive_file = output_dir / "live_hosts.txt"
    dirs_dir = output_dir / "directories"
    dirs_dir.mkdir(exist_ok=True)
    
    if not alive_file.exists() or alive_file.stat().st_size == 0:
        logger.warning("No live hosts file found. Skipping directory bruteforce.")
        return False
    
    if not check_tool_exists('ffuf'):
        logger.error("ffuf not found. Install: go install github.com/ffuf/ffuf/v2@latest")
        return False
    
    # Default wordlist locations (common on Kali/security distros)
    default_wordlists = [
        '/usr/share/wordlists/dirb/common.txt',
        '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
        '/usr/share/seclists/Discovery/Web-Content/common.txt',
        '/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt'
    ]
    
    if wordlist and os.path.exists(wordlist):
        selected_wordlist = wordlist
    else:
        selected_wordlist = None
        for wl in default_wordlists:
            if os.path.exists(wl):
                selected_wordlist = wl
                break
    
    if not selected_wordlist:
        logger.error("No wordlist found. Specify with --wordlist or install seclists")
        return False
    
    logger.info(f"Using wordlist: {selected_wordlist}")
    
    # Extract URLs
    urls = []
    with open(alive_file, 'r') as f:
        for line in f:
            url = line.split()[0] if line.strip() else None
            if url and url.startswith('http'):
                urls.append(url.rstrip('/'))
    
    if not urls:
        logger.warning("No valid URLs for directory bruteforcing")
        return False
    
    logger.info(f"Bruteforcing directories on {len(urls)} hosts...")
    
    results_found = 0
    for i, url in enumerate(urls, 1):
        rate_limiter.wait()
        
        # Create safe filename from URL
        safe_name = re.sub(r'[^\w\-.]', '_', url.replace('https://', '').replace('http://', ''))
        output_file = dirs_dir / f"{safe_name}.json"
        
        logger.info(f"[{i}/{len(urls)}] Scanning: {url}")
        
        ffuf_args = [
            'ffuf',
            '-u', f"{url}/FUZZ",
            '-w', selected_wordlist,
            '-t', str(threads),
            '-mc', '200,201,202,204,301,302,307,401,403,405,500',  # Match codes
            '-fc', '404',                # Filter 404s
            '-sf',                       # Stop on spurious responses
            '-se',                       # Stop on errors
            '-ac',                       # Auto-calibrate filtering
            '-o', str(output_file),
            '-of', 'json',
            '-s'                         # Silent mode
        ]
        
        # Add extension fuzzing
        if extensions:
            ffuf_args.extend(['-e', extensions])
        
        run_command(ffuf_args, timeout=COMMAND_TIMEOUT)
        
        if output_file.exists() and output_file.stat().st_size > 100:  # More than empty JSON
            results_found += 1
    
    # Combine all results
    combined_file = output_dir / "directories_combined.txt"
    with open(combined_file, 'w') as outf:
        for json_file in dirs_dir.glob('*.json'):
            try:
                with open(json_file, 'r') as jf:
                    data = json.load(jf)
                    if 'results' in data:
                        for result in data['results']:
                            outf.write(f"{result.get('url', '')} [{result.get('status', '')}] [{result.get('length', '')}]\n")
            except (json.JSONDecodeError, KeyError):
                continue
    
    if combined_file.exists() and combined_file.stat().st_size > 0:
        dir_count = count_lines_safely(combined_file)
        logger.info(f"Found {dir_count} directories/files across {results_found} hosts")
        return True
    else:
        logger.info("No hidden directories/files found")
        return True


def module_ssl_analysis(output_dir):
    """
    Phase 8: SSL/TLS Analysis
    Analyzes SSL/TLS configurations using testssl.sh.
    """
    logger.info("Starting Phase 8: SSL/TLS Analysis")
    
    alive_file = output_dir / "live_hosts.txt"
    ssl_dir = output_dir / "ssl_analysis"
    ssl_dir.mkdir(exist_ok=True)
    
    if not alive_file.exists() or alive_file.stat().st_size == 0:
        logger.warning("No live hosts file found. Skipping SSL analysis.")
        return False
    
    # Check for testssl.sh
    testssl_cmd = None
    for cmd in ['testssl.sh', 'testssl']:
        if check_tool_exists(cmd):
            testssl_cmd = cmd
            break
    
    if not testssl_cmd:
        logger.error("testssl.sh not found. Install: apt install testssl.sh or git clone https://github.com/drwetter/testssl.sh")
        return False
    
    # Extract HTTPS URLs only
    https_hosts = []
    with open(alive_file, 'r') as f:
        for line in f:
            url = line.split()[0] if line.strip() else None
            if url and url.startswith('https://'):
                # Extract host:port
                host = url.replace('https://', '').split('/')[0]
                if host not in https_hosts:
                    https_hosts.append(host)
    
    if not https_hosts:
        logger.warning("No HTTPS hosts found for SSL analysis")
        return False
    
    logger.info(f"Analyzing SSL/TLS on {len(https_hosts)} HTTPS hosts...")
    
    ssl_summary = output_dir / "ssl_summary.txt"
    issues_found = []
    
    for i, host in enumerate(https_hosts, 1):
        rate_limiter.wait()
        
        safe_name = re.sub(r'[^\w\-.]', '_', host)
        output_file = ssl_dir / f"{safe_name}.txt"
        json_file = ssl_dir / f"{safe_name}.json"
        
        logger.info(f"[{i}/{len(https_hosts)}] Testing: {host}")
        
        # Run testssl.sh with key security checks
        testssl_args = [
            testssl_cmd,
            '--quiet',
            '--color', '0',
            '--jsonfile', str(json_file),
            '--logfile', str(output_file),
            '-p',                        # Protocols
            '-s',                        # Standard cipher suites
            '-f',                        # Check certificate
            '-U',                        # Vulnerabilities (BEAST, POODLE, etc.)
            host
        ]
        
        run_command(testssl_args, timeout=COMMAND_TIMEOUT * 2)
        
        # Quick parse for critical issues
        if json_file.exists():
            try:
                with open(json_file, 'r') as jf:
                    data = json.load(jf)
                    for finding in data:
                        if isinstance(finding, dict):
                            severity = finding.get('severity', '').upper()
                            if severity in ['CRITICAL', 'HIGH', 'MEDIUM']:
                                issues_found.append({
                                    'host': host,
                                    'id': finding.get('id', ''),
                                    'finding': finding.get('finding', ''),
                                    'severity': severity
                                })
            except (json.JSONDecodeError, TypeError):
                pass
    
    # Write summary
    with open(ssl_summary, 'w') as f:
        f.write("SSL/TLS Analysis Summary\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Hosts analyzed: {len(https_hosts)}\n")
        f.write(f"Issues found: {len(issues_found)}\n\n")
        
        if issues_found:
            f.write("Critical/High/Medium Findings:\n")
            f.write("-" * 30 + "\n")
            for issue in issues_found:
                f.write(f"[{issue['severity']}] {issue['host']}: {issue['id']} - {issue['finding']}\n")
    
    logger.info(f"SSL analysis complete. Found {len(issues_found)} security issues")
    logger.info(f"Results saved to: {ssl_dir}")
    return True


def module_waf_detect(output_dir):
    """
    Phase 9: WAF Detection
    Detects and fingerprints Web Application Firewalls using wafw00f.
    """
    logger.info("Starting Phase 9: WAF Detection")
    
    alive_file = output_dir / "live_hosts.txt"
    waf_file = output_dir / "waf_detection.txt"
    waf_json = output_dir / "waf_detection.json"
    
    if not alive_file.exists() or alive_file.stat().st_size == 0:
        logger.warning("No live hosts file found. Skipping WAF detection.")
        return False
    
    if not check_tool_exists('wafw00f'):
        logger.error("wafw00f not found. Install: pip install wafw00f")
        return False
    
    # Extract URLs
    urls = []
    with open(alive_file, 'r') as f:
        for line in f:
            url = line.split()[0] if line.strip() else None
            if url and url.startswith('http'):
                urls.append(url)
    
    if not urls:
        logger.warning("No valid URLs for WAF detection")
        return False
    
    urls_file = output_dir / "urls_for_waf.txt"
    with open(urls_file, 'w') as f:
        f.write('\n'.join(urls))
    
    logger.info(f"Detecting WAFs on {len(urls)} hosts...")
    rate_limiter.wait()
    
    # Run wafw00f
    wafw00f_args = [
        'wafw00f',
        '-i', str(urls_file),
        '-o', str(waf_json),
        '-f', 'json',
        '-a'                            # Test all WAF signatures
    ]
    
    result = run_command(wafw00f_args, output_file=str(waf_file))
    
    # Parse results for summary
    wafs_detected = {}
    if waf_json.exists():
        try:
            with open(waf_json, 'r') as f:
                data = json.load(f)
                for entry in data:
                    if isinstance(entry, dict):
                        url = entry.get('url', '')
                        waf = entry.get('firewall', entry.get('detected', 'None'))
                        if waf and waf != 'None':
                            wafs_detected[url] = waf
        except (json.JSONDecodeError, TypeError):
            pass
    
    # Write human-readable summary
    with open(waf_file, 'w') as f:
        f.write("WAF Detection Results\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Hosts scanned: {len(urls)}\n")
        f.write(f"WAFs detected: {len(wafs_detected)}\n\n")
        
        if wafs_detected:
            f.write("Detected WAFs:\n")
            f.write("-" * 30 + "\n")
            for url, waf in wafs_detected.items():
                f.write(f"{url}: {waf}\n")
        else:
            f.write("No WAFs detected (targets may be unprotected)\n")
    
    logger.info(f"WAF detection complete. Found {len(wafs_detected)} WAF-protected hosts")
    logger.info(f"Results saved to: {waf_file}")
    return True


def module_api_discovery(output_dir, depth=3, crawl_duration=300, skip_historical=False):
    """
    Phase 10: API Endpoint Discovery
    Discovers API endpoints using multiple sources:
    - katana: Active crawling
    - gau: GetAllUrls from various sources (skipped for IPs)
    - waybackurls: Historical URLs from Wayback Machine (skipped for IPs)
    
    Args:
        skip_historical: If True, skip gau and waybackurls (for IP targets)
    """
    logger.info("Starting Phase 10: API Endpoint Discovery")
    
    alive_file = output_dir / "live_hosts.txt"
    subs_file = output_dir / "subdomains.txt"
    api_dir = output_dir / "api_discovery"
    api_dir.mkdir(exist_ok=True)
    
    # Output files
    all_urls_file = api_dir / "all_urls.txt"
    api_endpoints_file = output_dir / "api_endpoints.txt"
    api_params_file = api_dir / "parameters.txt"
    api_js_files = api_dir / "js_files.txt"
    api_json = output_dir / "api_endpoints.json"
    
    if not alive_file.exists() or alive_file.stat().st_size == 0:
        logger.warning("No live hosts file found. Skipping API discovery.")
        return False
    
    # Extract base URLs and domains
    urls = []
    domains = set()
    with open(alive_file, 'r') as f:
        for line in f:
            url = line.split()[0] if line.strip() else None
            if url and url.startswith('http'):
                urls.append(url)
                # Extract domain
                domain = re.sub(r'^https?://', '', url).split('/')[0].split(':')[0]
                domains.add(domain)
    
    if not urls:
        logger.warning("No valid URLs for API discovery")
        return False
    
    urls_file = api_dir / "urls_for_api.txt"
    domains_file = api_dir / "domains_for_api.txt"
    with open(urls_file, 'w') as f:
        f.write('\n'.join(urls))
    with open(domains_file, 'w') as f:
        f.write('\n'.join(domains))
    
    all_discovered_urls = set()
    
    # Tool 1: Katana (Active Crawler)
    if check_tool_exists('katana'):
        logger.info(f"Running Katana crawler (depth={depth})...")
        rate_limiter.wait()
        
        katana_output = api_dir / "katana_urls.txt"
        katana_args = [
            'katana',
            '-list', str(urls_file),
            '-d', str(depth),               # Crawl depth
            '-jc',                           # JavaScript crawling
            '-kf', 'all',                    # Known files (robots.txt, sitemap, etc.)
            '-ef', 'css,png,jpg,jpeg,gif,svg,woff,woff2,ttf,eot,ico',  # Exclude static
            '-o', str(katana_output),
            '-silent',
            '-nc',                           # No color
            '-timeout', '10',
            '-rate-limit', '50',
            '-crawl-duration', str(crawl_duration)
        ]
        
        run_command(katana_args, timeout=crawl_duration + 60)
        
        if katana_output.exists():
            with open(katana_output, 'r') as f:
                for line in f:
                    all_discovered_urls.add(line.strip())
            logger.info(f"Katana found {count_lines_safely(katana_output)} URLs")
    else:
        logger.warning("katana not found. Install: go install github.com/projectdiscovery/katana/cmd/katana@latest")
    
    # Tool 2: GAU (GetAllUrls) - Skip for IP targets
    if skip_historical:
        logger.info("Skipping GAU (historical URLs not available for IP targets)")
    elif check_tool_exists('gau'):
        logger.info("Running GAU (GetAllUrls)...")
        rate_limiter.wait()
        
        gau_output = api_dir / "gau_urls.txt"
        gau_args = [
            'gau',
            '--threads', '5',
            '--timeout', '30',
            '--retries', '2',
            '--blacklist', 'css,png,jpg,jpeg,gif,svg,woff,woff2,ttf,eot,ico,mp4,mp3,pdf'
        ]
        
        result = run_command(gau_args, input_file=str(domains_file), output_file=str(gau_output))
        
        if gau_output.exists():
            with open(gau_output, 'r') as f:
                for line in f:
                    all_discovered_urls.add(line.strip())
            logger.info(f"GAU found {count_lines_safely(gau_output)} URLs")
    else:
        logger.warning("gau not found. Install: go install github.com/lc/gau/v2/cmd/gau@latest")
    
    # Tool 3: Waybackurls - Skip for IP targets
    if skip_historical:
        logger.info("Skipping Waybackurls (historical URLs not available for IP targets)")
    elif check_tool_exists('waybackurls'):
        logger.info("Running Waybackurls...")
        rate_limiter.wait()
        
        wayback_output = api_dir / "wayback_urls.txt"
        wayback_args = ['waybackurls']
        
        result = run_command(wayback_args, input_file=str(domains_file), output_file=str(wayback_output))
        
        if wayback_output.exists():
            with open(wayback_output, 'r') as f:
                for line in f:
                    all_discovered_urls.add(line.strip())
            logger.info(f"Waybackurls found {count_lines_safely(wayback_output)} URLs")
    else:
        logger.warning("waybackurls not found. Install: go install github.com/tomnomnom/waybackurls@latest")
    
    if not all_discovered_urls:
        logger.warning("No URLs discovered from any source")
        return False
    
    # Write all unique URLs
    with open(all_urls_file, 'w') as f:
        f.write('\n'.join(sorted(all_discovered_urls)))
    
    logger.info(f"Total unique URLs discovered: {len(all_discovered_urls)}")
    
    # Filter and categorize URLs
    api_patterns = [
        r'/api/',
        r'/api/v[0-9]+',
        r'/v[0-9]+/',
        r'/rest/',
        r'/graphql',
        r'/query',
        r'/mutation',
        r'/swagger',
        r'/openapi',
        r'/docs/api',
        r'/api-docs',
        r'/_api/',
        r'/ajax/',
        r'/json/',
        r'/xml/',
        r'/rpc/',
        r'/soap/',
        r'/ws/',
        r'/websocket',
        r'/oauth',
        r'/auth/',
        r'/token',
        r'/login',
        r'/register',
        r'/users',
        r'/account',
        r'/admin',
        r'/internal',
        r'/private',
        r'/debug',
        r'/test',
        r'/dev/',
        r'/staging',
        r'/backend',
        r'\.json$',
        r'\.xml$',
        r'\.yaml$',
        r'\.yml$'
    ]
    
    api_pattern = re.compile('|'.join(api_patterns), re.IGNORECASE)
    js_pattern = re.compile(r'\.js(\?|$)', re.IGNORECASE)
    param_pattern = re.compile(r'\?.*=')
    
    api_endpoints = set()
    js_files = set()
    params_urls = set()
    
    for url in all_discovered_urls:
        if api_pattern.search(url):
            api_endpoints.add(url)
        if js_pattern.search(url):
            js_files.add(url)
        if param_pattern.search(url):
            params_urls.add(url)
    
    # Write categorized results
    with open(api_endpoints_file, 'w') as f:
        f.write('\n'.join(sorted(api_endpoints)))
    
    with open(api_js_files, 'w') as f:
        f.write('\n'.join(sorted(js_files)))
    
    with open(api_params_file, 'w') as f:
        f.write('\n'.join(sorted(params_urls)))
    
    # Extract unique parameters
    unique_params = set()
    for url in params_urls:
        try:
            query = url.split('?')[1] if '?' in url else ''
            for param in query.split('&'):
                if '=' in param:
                    param_name = param.split('=')[0]
                    unique_params.add(param_name)
        except IndexError:
            continue
    
    # Create JSON summary
    api_summary = {
        'total_urls_discovered': len(all_discovered_urls),
        'api_endpoints_count': len(api_endpoints),
        'js_files_count': len(js_files),
        'urls_with_params_count': len(params_urls),
        'unique_parameters': sorted(unique_params),
        'api_endpoints_sample': sorted(list(api_endpoints))[:100],
        'interesting_js_files': sorted([js for js in js_files if any(kw in js.lower() for kw in ['api', 'config', 'app', 'main', 'bundle'])])[:50]
    }
    
    with open(api_json, 'w') as f:
        json.dump(api_summary, f, indent=2)
    
    # Log summary
    logger.info(f"API Endpoints found: {len(api_endpoints)}")
    logger.info(f"JavaScript files found: {len(js_files)}")
    logger.info(f"URLs with parameters: {len(params_urls)}")
    logger.info(f"Unique parameters: {len(unique_params)}")
    logger.info(f"Results saved to: {api_dir}")
    
    # Additional: Extract potential secrets patterns from JS files (basic)
    secrets_file = api_dir / "potential_secrets.txt"
    secret_patterns = [
        (r'["\']?api[_-]?key["\']?\s*[:=]\s*["\'][^"\']+', 'API Key'),
        (r'["\']?secret[_-]?key["\']?\s*[:=]\s*["\'][^"\']+', 'Secret Key'),
        (r'["\']?password["\']?\s*[:=]\s*["\'][^"\']+', 'Password'),
        (r'["\']?token["\']?\s*[:=]\s*["\'][^"\']+', 'Token'),
        (r'["\']?auth[_-]?token["\']?\s*[:=]\s*["\'][^"\']+', 'Auth Token'),
        (r'["\']?access[_-]?token["\']?\s*[:=]\s*["\'][^"\']+', 'Access Token'),
        (r'["\']?client[_-]?secret["\']?\s*[:=]\s*["\'][^"\']+', 'Client Secret'),
        (r'["\']?private[_-]?key["\']?\s*[:=]\s*["\'][^"\']+', 'Private Key'),
        (r'Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+', 'JWT Token'),
        (r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+', 'JWT'),
        (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
        (r'["\']?aws[_-]?secret["\']?\s*[:=]\s*["\'][^"\']+', 'AWS Secret'),
    ]
    
    with open(secrets_file, 'w') as f:
        f.write("Potential Secrets Pattern Matches (Review Manually)\n")
        f.write("=" * 50 + "\n\n")
        f.write("Note: These are pattern matches from URL paths.\n")
        f.write("For deeper analysis, fetch and scan JS files.\n\n")
        
        for url in list(js_files)[:20]:  # Check first 20 JS files in URLs
            for pattern, name in secret_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    f.write(f"[{name}] {url}\n")
    
    return True


def generate_report(output_dir, target_domain):
    """
    Generate a summary report of all findings.
    """
    logger.info("Generating summary report...")
    
    report_file = output_dir / "report.md"
    
    with open(report_file, 'w') as f:
        f.write(f"# ASM Report: {target_domain}\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("---\n\n")
        
        # Subdomain count
        subs_file = output_dir / "subdomains.txt"
        if subs_file.exists():
            count = count_lines_safely(subs_file)
            f.write(f"## Subdomains Discovered: {count}\n\n")
        
        # Live hosts count
        alive_file = output_dir / "live_hosts.txt"
        if alive_file.exists():
            count = count_lines_safely(alive_file)
            f.write(f"## Live Hosts: {count}\n\n")
        
        # Vulnerabilities
        vuln_file = output_dir / "vulnerabilities.txt"
        if vuln_file.exists() and vuln_file.stat().st_size > 0:
            count = count_lines_safely(vuln_file)
            f.write(f"## ⚠️ Vulnerabilities Found: {count}\n\n")
            f.write("```\n")
            with open(vuln_file, 'r') as vf:
                f.write(vf.read()[:5000])  # First 5KB
            f.write("\n```\n\n")
        else:
            f.write("## ✅ No Vulnerabilities Detected\n\n")
        
        # Screenshots
        screenshot_dir = output_dir / "screenshots"
        if screenshot_dir.exists():
            screenshots = list(screenshot_dir.glob('*.png'))
            f.write(f"## Screenshots Captured: {len(screenshots)}\n\n")
        
        # DNS Records
        dns_file = output_dir / "dns_records.txt"
        if dns_file.exists() and dns_file.stat().st_size > 0:
            count = count_lines_safely(dns_file)
            f.write(f"## DNS Records: {count}\n\n")
        
        # Directory Bruteforce
        dirs_file = output_dir / "directories_combined.txt"
        if dirs_file.exists() and dirs_file.stat().st_size > 0:
            count = count_lines_safely(dirs_file)
            f.write(f"## Hidden Directories/Files: {count}\n\n")
        
        # SSL/TLS Issues
        ssl_summary = output_dir / "ssl_summary.txt"
        if ssl_summary.exists():
            f.write("## SSL/TLS Analysis\n\n")
            f.write("```\n")
            with open(ssl_summary, 'r') as sf:
                f.write(sf.read()[:3000])
            f.write("\n```\n\n")
        
        # WAF Detection
        waf_file = output_dir / "waf_detection.txt"
        if waf_file.exists():
            f.write("## WAF Detection\n\n")
            f.write("```\n")
            with open(waf_file, 'r') as wf:
                f.write(wf.read()[:2000])
            f.write("\n```\n\n")
        
        # API Discovery
        api_json = output_dir / "api_endpoints.json"
        api_file = output_dir / "api_endpoints.txt"
        if api_json.exists():
            try:
                with open(api_json, 'r') as af:
                    api_data = json.load(af)
                f.write("## 🔌 API Discovery\n\n")
                f.write(f"- **Total URLs crawled:** {api_data.get('total_urls_discovered', 0)}\n")
                f.write(f"- **API endpoints found:** {api_data.get('api_endpoints_count', 0)}\n")
                f.write(f"- **JavaScript files:** {api_data.get('js_files_count', 0)}\n")
                f.write(f"- **URLs with parameters:** {api_data.get('urls_with_params_count', 0)}\n")
                f.write(f"- **Unique parameters:** {len(api_data.get('unique_parameters', []))}\n\n")
                
                if api_data.get('unique_parameters'):
                    f.write("**Parameters found:**\n```\n")
                    f.write(', '.join(api_data['unique_parameters'][:50]))
                    f.write("\n```\n\n")
                
                if api_data.get('api_endpoints_sample'):
                    f.write("**Sample API endpoints:**\n```\n")
                    for endpoint in api_data['api_endpoints_sample'][:20]:
                        f.write(f"{endpoint}\n")
                    f.write("\n```\n\n")
            except (json.JSONDecodeError, KeyError):
                pass
        elif api_file.exists() and api_file.stat().st_size > 0:
            count = count_lines_safely(api_file)
            f.write(f"## API Endpoints Discovered: {count}\n\n")
        
        f.write("---\n")
        f.write(f"\n*Report generated by ASM Tool*\n")
    
    logger.info(f"Report saved to: {report_file}")
    return report_file

def main():
    """Main entry point with argument parsing."""
    parser = argparse.ArgumentParser(
        description="ASM Recon Tool - Attack Surface Management",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t example.com                    # Run all modules (full ASM scan)
  %(prog)s -t example.com --discovery-only   # Only subdomain discovery
  %(prog)s -t example.com --skip-vuln        # Skip vulnerability scanning
  %(prog)s -t example.com --skip-dirs        # Skip directory bruteforcing  
  %(prog)s -t example.com --rate-limit 2.0   # 2 seconds between requests (stealth)
  %(prog)s -t example.com --top-ports 100    # Scan top 100 ports only
  %(prog)s -t example.com --wordlist /path/to/wordlist.txt  # Custom wordlist
  %(prog)s -t example.com --skip-ssl --skip-waf  # Skip SSL and WAF checks
  %(prog)s -t example.com --crawl-depth 5    # Deeper API crawling
  %(prog)s -t example.com --skip-api         # Skip API endpoint discovery
        """
    )
    
    # Target options
    parser.add_argument(
        "-t", "--target",
        help="The target domain (e.g., example.com)",
        required=True
    )
    
    # Module control flags
    parser.add_argument(
        "--discovery-only",
        action="store_true",
        help="Run only subdomain discovery and live host check"
    )
    parser.add_argument(
        "--skip-ports",
        action="store_true",
        help="Skip port scanning"
    )
    parser.add_argument(
        "--skip-tech",
        action="store_true",
        help="Skip technology detection"
    )
    parser.add_argument(
        "--skip-vuln",
        action="store_true",
        help="Skip vulnerability scanning"
    )
    parser.add_argument(
        "--skip-screenshots",
        action="store_true",
        help="Skip screenshot capture"
    )
    parser.add_argument(
        "--skip-dns",
        action="store_true",
        help="Skip DNS enumeration"
    )
    parser.add_argument(
        "--skip-dirs",
        action="store_true",
        help="Skip directory bruteforcing"
    )
    parser.add_argument(
        "--skip-ssl",
        action="store_true",
        help="Skip SSL/TLS analysis"
    )
    parser.add_argument(
        "--skip-waf",
        action="store_true",
        help="Skip WAF detection"
    )
    parser.add_argument(
        "--skip-api",
        action="store_true",
        help="Skip API endpoint discovery"
    )
    
    # Module configuration
    parser.add_argument(
        "--top-ports",
        type=int,
        default=1000,
        help="Number of top ports to scan (default: 1000)"
    )
    parser.add_argument(
        "--vuln-severity",
        type=str,
        default="medium,high,critical",
        help="Vulnerability severity filter (default: medium,high,critical)"
    )
    parser.add_argument(
        "--nuclei-templates",
        type=str,
        default=None,
        help="Custom nuclei templates path"
    )
    parser.add_argument(
        "--screenshot-threads",
        type=int,
        default=4,
        help="Number of threads for screenshots (default: 4)"
    )
    parser.add_argument(
        "--wordlist",
        type=str,
        default=None,
        help="Custom wordlist for directory bruteforcing"
    )
    parser.add_argument(
        "--ffuf-threads",
        type=int,
        default=50,
        help="Number of threads for ffuf (default: 50)"
    )
    parser.add_argument(
        "--extensions",
        type=str,
        default="php,asp,aspx,jsp,html,js,txt,bak",
        help="File extensions to fuzz (default: php,asp,aspx,jsp,html,js,txt,bak)"
    )
    parser.add_argument(
        "--crawl-depth",
        type=int,
        default=3,
        help="Katana crawl depth for API discovery (default: 3)"
    )
    parser.add_argument(
        "--crawl-duration",
        type=int,
        default=300,
        help="Max crawl duration in seconds (default: 300)"
    )
    
    # General options
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose/debug output"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Command timeout in seconds (default: 300)"
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=1.0,
        help="Delay between module executions in seconds (default: 1.0)"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Custom output directory (default: auto-generated)"
    )
    
    args = parser.parse_args()
    
    # Configure settings from arguments
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    global COMMAND_TIMEOUT
    COMMAND_TIMEOUT = args.timeout
    
    rate_limiter.set_delay(args.rate_limit)
    
    # Print banner
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║           ASM - Attack Surface Management Tool            ║
    ║                   Security Reconnaissance                 ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    logger.info(f"Target: {args.target}")
    logger.info(f"Rate limit: {args.rate_limit}s | Timeout: {args.timeout}s")
    
    # Phase 1: Discovery (always runs)
    output_dir = module_discovery(args.target)
    
    if not output_dir:
        logger.error("Discovery phase failed. Exiting.")
        sys.exit(1)
    
    # If discovery only, stop here
    if args.discovery_only:
        logger.info("Discovery-only mode. Stopping here.")
        generate_report(output_dir, args.target)
        sys.exit(0)
    
    # Phase 2: Port Scanning
    if not args.skip_ports:
        module_port_scan(output_dir, top_ports=args.top_ports)
    else:
        logger.info("Skipping port scanning (--skip-ports)")
    
    # Phase 3: Technology Detection
    if not args.skip_tech:
        module_tech_detect(output_dir)
    else:
        logger.info("Skipping technology detection (--skip-tech)")
    
    # Phase 4: Vulnerability Scanning
    if not args.skip_vuln:
        module_vuln_scan(
            output_dir,
            severity=args.vuln_severity,
            templates=args.nuclei_templates
        )
    else:
        logger.info("Skipping vulnerability scanning (--skip-vuln)")
    
    # Phase 5: Screenshots
    if not args.skip_screenshots:
        module_screenshot(output_dir, threads=args.screenshot_threads)
    else:
        logger.info("Skipping screenshot capture (--skip-screenshots)")
    
    # Phase 6: DNS Enumeration
    if not args.skip_dns:
        module_dns_enum(output_dir, args.target)
    else:
        logger.info("Skipping DNS enumeration (--skip-dns)")
    
    # Phase 7: Directory Bruteforcing
    if not args.skip_dirs:
        module_dir_bruteforce(
            output_dir,
            wordlist=args.wordlist,
            threads=args.ffuf_threads,
            extensions=args.extensions
        )
    else:
        logger.info("Skipping directory bruteforcing (--skip-dirs)")
    
    # Phase 8: SSL/TLS Analysis
    if not args.skip_ssl:
        module_ssl_analysis(output_dir)
    else:
        logger.info("Skipping SSL/TLS analysis (--skip-ssl)")
    
    # Phase 9: WAF Detection
    if not args.skip_waf:
        module_waf_detect(output_dir)
    else:
        logger.info("Skipping WAF detection (--skip-waf)")
    
    # Phase 10: API Endpoint Discovery
    if not args.skip_api:
        module_api_discovery(
            output_dir,
            depth=args.crawl_depth,
            crawl_duration=args.crawl_duration
        )
    else:
        logger.info("Skipping API discovery (--skip-api)")
    
    # Generate final report
    generate_report(output_dir, args.target)
    
    logger.info("=" * 60)
    logger.info("ASM scan completed successfully!")
    logger.info(f"All results saved in: {output_dir}")
    logger.info("=" * 60)
    
    sys.exit(0)


if __name__ == "__main__":
    main()