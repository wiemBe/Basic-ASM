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
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('asm_audit.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configuration constants
COMMAND_TIMEOUT = 300  # 5 minutes max per command
OUTPUT_DIR = "asm_output"
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

def validate_domain(domain):
    """
    Validate domain format to prevent command injection.
    Only allows valid domain characters: alphanumeric, hyphens, and dots.
    """
    # Strict regex for valid domain names
    domain_pattern = re.compile(
        r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)'  # Labels (no leading/trailing hyphens)
        r'(\.[A-Za-z0-9-]{1,63})*'          # Additional labels
        r'\.[A-Za-z]{2,}$'                   # TLD
    )
    
    if not domain_pattern.match(domain):
        raise ValueError(f"Invalid domain format: {domain}")
    
    # Additional security checks
    dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '\n', '\r']
    if any(char in domain for char in dangerous_chars):
        raise ValueError(f"Domain contains forbidden characters: {domain}")
    
    return domain

def check_tool_exists(tool_name):
    """Verify required tools are installed before running."""
    if shutil.which(tool_name) is None:
        logger.error(f"Required tool '{tool_name}' not found in PATH")
        return False
    return True

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
        
        logger.info(f"Executing: {' '.join(command_args)}")
        
        result = subprocess.run(
            command_args,
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
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_domain = re.sub(r'[^\w\-.]', '_', target_domain)
    output_path = Path(OUTPUT_DIR) / f"{safe_domain}_{timestamp}"
    output_path.mkdir(parents=True, exist_ok=True)
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
    
    # Check required tools exist
    required_tools = ['subfinder', 'httpx-toolkit']
    for tool in required_tools:
        if not check_tool_exists(tool):
            logger.error(f"Missing required tool: {tool}. Please install it first.")
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
    httpx_args = ['httpx-toolkit', '-silent', '-sc', '-title']
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
  %(prog)s -t example.com                    # Run all modules
  %(prog)s -t example.com --discovery-only   # Only subdomain discovery
  %(prog)s -t example.com --skip-vuln        # Skip vulnerability scanning
  %(prog)s -t example.com --rate-limit 2.0   # 2 seconds between requests
  %(prog)s -t example.com --top-ports 100    # Scan top 100 ports only
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
    
    # Generate final report
    generate_report(output_dir, args.target)
    
    logger.info("=" * 60)
    logger.info("ASM scan completed successfully!")
    logger.info(f"All results saved in: {output_dir}")
    logger.info("=" * 60)
    
    sys.exit(0)


if __name__ == "__main__":
    main()