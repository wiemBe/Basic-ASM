"""
ASM Tool - Web GUI
A Flask-based web interface for the Attack Surface Management tool.
Run with: python gui.py
Access at: http://localhost:5000
"""

import os
import sys
import json
import threading
import queue
import time
import re
from pathlib import Path
from datetime import datetime
from flask import Flask, render_template, request, jsonify, Response, send_from_directory
from flask_socketio import SocketIO, emit

# Import the core ASM functions from main.py
from main import (
    validate_domain,
    check_tool_exists,
    run_command,
    count_lines_safely,
    setup_output_directory,
    rate_limiter,
    module_discovery,
    module_port_scan,
    module_tech_detect,
    module_vuln_scan,
    module_screenshot,
    module_dns_enum,
    module_dir_bruteforce,
    module_ssl_analysis,
    module_waf_detect,
    module_api_discovery,
    generate_report,
    logger,
    COMMAND_TIMEOUT
)

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SECRET_KEY'] = os.urandom(24)
socketio = SocketIO(app, cors_allowed_origins="*")

# Global state for scan management
active_scans = {}
scan_logs = {}

class ScanManager:
    """Manages ASM scan execution and progress tracking."""
    
    def __init__(self, scan_id, target, options):
        self.scan_id = scan_id
        self.target = target
        self.options = options
        self.status = "pending"
        self.current_phase = ""
        self.progress = 0
        self.results = {}
        self.output_dir = None
        self.logs = []
        self.start_time = None
        self.end_time = None
        
    def log(self, message, level="info"):
        """Add log message and emit to frontend."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = {"time": timestamp, "level": level, "message": message}
        self.logs.append(log_entry)
        socketio.emit('scan_log', {
            'scan_id': self.scan_id,
            'log': log_entry
        })
        
    def update_progress(self, phase, progress, status="running"):
        """Update scan progress and emit to frontend."""
        self.current_phase = phase
        self.progress = progress
        self.status = status
        socketio.emit('scan_progress', {
            'scan_id': self.scan_id,
            'phase': phase,
            'progress': progress,
            'status': status
        })
    
    def run_scan(self):
        """Execute the full ASM scan pipeline."""
        self.start_time = datetime.now()
        self.status = "running"
        
        try:
            # Validate target
            self.log(f"Starting scan for: {self.target}")
            self.update_progress("Validation", 5)
            
            try:
                validated_target = validate_domain(self.target)
            except ValueError as e:
                self.log(f"Invalid target: {e}", "error")
                self.update_progress("Failed", 0, "failed")
                return
            
            # Set rate limit from options
            rate_limiter.set_delay(self.options.get('rate_limit', 1.0))
            
            # Phase 1: Discovery
            self.update_progress("Subdomain Discovery", 10)
            self.log("Phase 1: Running subdomain discovery...")
            self.output_dir = module_discovery(validated_target)
            
            if not self.output_dir:
                self.log("Discovery failed!", "error")
                self.update_progress("Failed", 10, "failed")
                return
            
            self.log(f"Output directory: {self.output_dir}")
            self.results['output_dir'] = str(self.output_dir)
            
            # Count subdomains
            subs_file = self.output_dir / "subdomains.txt"
            if subs_file.exists():
                count = count_lines_safely(subs_file)
                self.results['subdomains'] = count
                self.log(f"Found {count} subdomains")
            
            # Count live hosts
            alive_file = self.output_dir / "live_hosts.txt"
            if alive_file.exists():
                count = count_lines_safely(alive_file)
                self.results['live_hosts'] = count
                self.log(f"Found {count} live hosts")
            
            # Check if discovery only
            if self.options.get('discovery_only'):
                self.log("Discovery-only mode. Generating report...")
                generate_report(self.output_dir, validated_target)
                self.update_progress("Completed", 100, "completed")
                self.end_time = datetime.now()
                return
            
            # Phase 2: Port Scanning
            if not self.options.get('skip_ports'):
                self.update_progress("Port Scanning", 20)
                self.log("Phase 2: Running port scan...")
                module_port_scan(self.output_dir, top_ports=self.options.get('top_ports', 1000))
                self.log("Port scan completed")
            else:
                self.log("Skipping port scanning")
            
            # Phase 3: Technology Detection
            if not self.options.get('skip_tech'):
                self.update_progress("Tech Detection", 30)
                self.log("Phase 3: Running technology detection...")
                module_tech_detect(self.output_dir)
                self.log("Technology detection completed")
            else:
                self.log("Skipping technology detection")
            
            # Phase 4: Vulnerability Scanning
            if not self.options.get('skip_vuln'):
                self.update_progress("Vulnerability Scan", 40)
                self.log("Phase 4: Running vulnerability scan...")
                module_vuln_scan(
                    self.output_dir,
                    severity=self.options.get('vuln_severity', 'medium,high,critical'),
                    templates=self.options.get('nuclei_templates')
                )
                vuln_file = self.output_dir / "vulnerabilities.txt"
                if vuln_file.exists() and vuln_file.stat().st_size > 0:
                    count = count_lines_safely(vuln_file)
                    self.results['vulnerabilities'] = count
                    self.log(f"Found {count} potential vulnerabilities!", "warning")
                else:
                    self.results['vulnerabilities'] = 0
                    self.log("No vulnerabilities found")
            else:
                self.log("Skipping vulnerability scanning")
            
            # Phase 5: Screenshots
            if not self.options.get('skip_screenshots'):
                self.update_progress("Screenshots", 50)
                self.log("Phase 5: Capturing screenshots...")
                module_screenshot(self.output_dir, threads=self.options.get('screenshot_threads', 4))
                screenshot_dir = self.output_dir / "screenshots"
                if screenshot_dir.exists():
                    count = len(list(screenshot_dir.glob('*.png')))
                    self.results['screenshots'] = count
                    self.log(f"Captured {count} screenshots")
            else:
                self.log("Skipping screenshot capture")
            
            # Phase 6: DNS Enumeration
            if not self.options.get('skip_dns'):
                self.update_progress("DNS Enumeration", 60)
                self.log("Phase 6: Running DNS enumeration...")
                module_dns_enum(self.output_dir, validated_target)
                self.log("DNS enumeration completed")
            else:
                self.log("Skipping DNS enumeration")
            
            # Phase 7: Directory Bruteforce
            if not self.options.get('skip_dirs'):
                self.update_progress("Directory Bruteforce", 70)
                self.log("Phase 7: Running directory bruteforce...")
                module_dir_bruteforce(
                    self.output_dir,
                    wordlist=self.options.get('wordlist'),
                    threads=self.options.get('ffuf_threads', 50),
                    extensions=self.options.get('extensions', 'php,asp,aspx,jsp,html,js,txt,bak')
                )
                self.log("Directory bruteforce completed")
            else:
                self.log("Skipping directory bruteforce")
            
            # Phase 8: SSL/TLS Analysis
            if not self.options.get('skip_ssl'):
                self.update_progress("SSL/TLS Analysis", 80)
                self.log("Phase 8: Running SSL/TLS analysis...")
                module_ssl_analysis(self.output_dir)
                self.log("SSL/TLS analysis completed")
            else:
                self.log("Skipping SSL/TLS analysis")
            
            # Phase 9: WAF Detection
            if not self.options.get('skip_waf'):
                self.update_progress("WAF Detection", 85)
                self.log("Phase 9: Running WAF detection...")
                module_waf_detect(self.output_dir)
                self.log("WAF detection completed")
            else:
                self.log("Skipping WAF detection")
            
            # Phase 10: API Discovery
            if not self.options.get('skip_api'):
                self.update_progress("API Discovery", 90)
                self.log("Phase 10: Running API endpoint discovery...")
                module_api_discovery(
                    self.output_dir,
                    depth=self.options.get('crawl_depth', 3),
                    crawl_duration=self.options.get('crawl_duration', 300)
                )
                api_file = self.output_dir / "api_endpoints.txt"
                if api_file.exists():
                    count = count_lines_safely(api_file)
                    self.results['api_endpoints'] = count
                    self.log(f"Found {count} API endpoints")
            else:
                self.log("Skipping API discovery")
            
            # Generate final report
            self.update_progress("Generating Report", 95)
            self.log("Generating final report...")
            generate_report(self.output_dir, validated_target)
            
            # Complete
            self.end_time = datetime.now()
            duration = (self.end_time - self.start_time).total_seconds()
            self.results['duration'] = f"{duration:.1f}s"
            self.log(f"Scan completed in {duration:.1f} seconds!")
            self.update_progress("Completed", 100, "completed")
            
        except Exception as e:
            self.log(f"Scan error: {str(e)}", "error")
            self.update_progress("Failed", self.progress, "failed")
            self.end_time = datetime.now()


def get_available_tools():
    """Check which ASM tools are installed."""
    tools = {
        'subfinder': check_tool_exists('subfinder'),
        'httpx-toolkit': check_tool_exists('httpx-toolkit'),
        'nmap': check_tool_exists('nmap'),
        'whatweb': check_tool_exists('whatweb'),
        'nuclei': check_tool_exists('nuclei'),
        'gowitness': check_tool_exists('gowitness'),
        'dnsx': check_tool_exists('dnsx'),
        'ffuf': check_tool_exists('ffuf'),
        'testssl.sh': check_tool_exists('testssl.sh') or check_tool_exists('testssl'),
        'wafw00f': check_tool_exists('wafw00f'),
        'katana': check_tool_exists('katana'),
        'gau': check_tool_exists('gau'),
        'waybackurls': check_tool_exists('waybackurls'),
    }
    return tools


def get_scan_results(output_dir):
    """Read and parse scan results from output directory."""
    results = {
        'subdomains': [],
        'live_hosts': [],
        'vulnerabilities': [],
        'technologies': [],
        'api_endpoints': [],
        'dns_records': [],
        'directories': [],
        'ssl_issues': [],
        'waf_detection': []
    }
    
    output_path = Path(output_dir)
    
    # Read subdomains
    subs_file = output_path / "subdomains.txt"
    if subs_file.exists():
        with open(subs_file, 'r') as f:
            results['subdomains'] = [line.strip() for line in f if line.strip()][:100]
    
    # Read live hosts
    alive_file = output_path / "live_hosts.txt"
    if alive_file.exists():
        with open(alive_file, 'r') as f:
            results['live_hosts'] = [line.strip() for line in f if line.strip()][:100]
    
    # Read vulnerabilities
    vuln_file = output_path / "vulnerabilities.txt"
    if vuln_file.exists():
        with open(vuln_file, 'r') as f:
            results['vulnerabilities'] = [line.strip() for line in f if line.strip()][:50]
    
    # Read API endpoints
    api_file = output_path / "api_endpoints.txt"
    if api_file.exists():
        with open(api_file, 'r') as f:
            results['api_endpoints'] = [line.strip() for line in f if line.strip()][:100]
    
    # Read report
    report_file = output_path / "report.md"
    if report_file.exists():
        with open(report_file, 'r') as f:
            results['report'] = f.read()
    
    return results


# ==================== ROUTES ====================

@app.route('/')
def index():
    """Main dashboard page."""
    return render_template('index.html')


@app.route('/api/tools')
def api_tools():
    """Get available tools status."""
    return jsonify(get_available_tools())


@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """Start a new ASM scan."""
    data = request.json
    target = data.get('target', '').strip()
    
    if not target:
        return jsonify({'error': 'Target domain is required'}), 400
    
    # Generate scan ID
    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    # Parse options
    options = {
        'discovery_only': data.get('discovery_only', False),
        'skip_ports': data.get('skip_ports', False),
        'skip_tech': data.get('skip_tech', False),
        'skip_vuln': data.get('skip_vuln', False),
        'skip_screenshots': data.get('skip_screenshots', False),
        'skip_dns': data.get('skip_dns', False),
        'skip_dirs': data.get('skip_dirs', False),
        'skip_ssl': data.get('skip_ssl', False),
        'skip_waf': data.get('skip_waf', False),
        'skip_api': data.get('skip_api', False),
        'top_ports': int(data.get('top_ports', 1000)),
        'vuln_severity': data.get('vuln_severity', 'medium,high,critical'),
        'rate_limit': float(data.get('rate_limit', 1.0)),
        'crawl_depth': int(data.get('crawl_depth', 3)),
        'crawl_duration': int(data.get('crawl_duration', 300)),
        'ffuf_threads': int(data.get('ffuf_threads', 50)),
        'screenshot_threads': int(data.get('screenshot_threads', 4)),
        'extensions': data.get('extensions', 'php,asp,aspx,jsp,html,js,txt,bak'),
        'wordlist': data.get('wordlist'),
        'nuclei_templates': data.get('nuclei_templates'),
    }
    
    # Create scan manager
    scan_manager = ScanManager(scan_id, target, options)
    active_scans[scan_id] = scan_manager
    
    # Start scan in background thread
    thread = threading.Thread(target=scan_manager.run_scan)
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'scan_id': scan_id,
        'target': target,
        'status': 'started'
    })


@app.route('/api/scan/<scan_id>/status')
def scan_status(scan_id):
    """Get scan status."""
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    
    scan = active_scans[scan_id]
    return jsonify({
        'scan_id': scan_id,
        'target': scan.target,
        'status': scan.status,
        'phase': scan.current_phase,
        'progress': scan.progress,
        'results': scan.results,
        'logs': scan.logs[-50:]  # Last 50 logs
    })


@app.route('/api/scan/<scan_id>/results')
def scan_results(scan_id):
    """Get detailed scan results."""
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    
    scan = active_scans[scan_id]
    if not scan.output_dir:
        return jsonify({'error': 'No results available yet'}), 400
    
    results = get_scan_results(scan.output_dir)
    results['scan_info'] = {
        'target': scan.target,
        'status': scan.status,
        'start_time': scan.start_time.isoformat() if scan.start_time else None,
        'end_time': scan.end_time.isoformat() if scan.end_time else None,
        'output_dir': str(scan.output_dir)
    }
    
    return jsonify(results)


@app.route('/api/scan/<scan_id>/stop', methods=['POST'])
def stop_scan(scan_id):
    """Stop a running scan."""
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    
    scan = active_scans[scan_id]
    scan.status = "stopped"
    scan.log("Scan stopped by user", "warning")
    
    return jsonify({'status': 'stopped'})


@app.route('/api/scans')
def list_scans():
    """List all scans."""
    scans = []
    for scan_id, scan in active_scans.items():
        scans.append({
            'scan_id': scan_id,
            'target': scan.target,
            'status': scan.status,
            'progress': scan.progress,
            'phase': scan.current_phase
        })
    return jsonify(scans)


@app.route('/api/previous-scans')
def previous_scans():
    """List previous scan results from disk."""
    output_dir = Path("asm_output")
    scans = []
    
    if output_dir.exists():
        for scan_dir in sorted(output_dir.iterdir(), reverse=True):
            if scan_dir.is_dir():
                report_file = scan_dir / "report.md"
                if report_file.exists():
                    # Extract domain from folder name
                    parts = scan_dir.name.rsplit('_', 2)
                    domain = parts[0] if len(parts) >= 3 else scan_dir.name
                    
                    scans.append({
                        'name': scan_dir.name,
                        'domain': domain,
                        'path': str(scan_dir),
                        'date': datetime.fromtimestamp(scan_dir.stat().st_mtime).isoformat()
                    })
    
    return jsonify(scans[:20])  # Last 20 scans


@app.route('/api/results/<path:scan_path>')
def get_results(scan_path):
    """Get results from a specific scan directory."""
    results = get_scan_results(scan_path)
    return jsonify(results)


# ==================== SOCKET.IO EVENTS ====================

@socketio.on('connect')
def handle_connect():
    """Handle client connection."""
    emit('connected', {'status': 'connected'})


@socketio.on('subscribe_scan')
def handle_subscribe(data):
    """Subscribe to scan updates."""
    scan_id = data.get('scan_id')
    if scan_id in active_scans:
        scan = active_scans[scan_id]
        emit('scan_status', {
            'scan_id': scan_id,
            'status': scan.status,
            'progress': scan.progress,
            'phase': scan.current_phase
        })


# ==================== MAIN ====================

if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    templates_dir = Path('templates')
    templates_dir.mkdir(exist_ok=True)
    
    static_dir = Path('static')
    static_dir.mkdir(exist_ok=True)
    
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║           ASM Tool - Web GUI                              ║
    ║           http://localhost:5000                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest github.com/projectdiscovery/httpx/cmd/httpx@latest github.com/projectdiscovery/dnsx/cmd/dnsx@latest github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest github.com/projectdiscovery/katana/cmd/katana@latest github.com/ffuf/ffuf/v2@latest github.com/sensepost/gowitness@latest github.com/lc/gau/v2/cmd/gau@latest github.com/tomnomnom/waybackurls@latest