"""
ASM Tool - AI Analysis Module
Integrates Google Gemini 1.5 for intelligent analysis of scan results.
"""

import os
import json
import logging
import time
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

# Rate limiting for free tier (15 RPM = 1 request per 4 seconds minimum)
GEMINI_RATE_LIMIT_DELAY = 5  # seconds between requests (safe for free tier)
_last_request_time = 0

# Try to import Google GenAI (new package)
try:
    from google import genai
    from google.genai import types
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    logger.warning("google-genai not installed. Run: pip install google-genai")


class GeminiAnalyzer:
    """AI-powered analysis using Google Gemini 1.5."""
    
    def __init__(self, api_key=None, lite_mode=False):
        """
        Initialize the Gemini analyzer.
        
        Args:
            api_key: Gemini API key. If None, looks for GEMINI_API_KEY env variable.
            lite_mode: If True, uses shorter prompts and fewer analyses (better for free tier)
        """
        self.api_key = api_key or os.environ.get('GEMINI_API_KEY')
        self.client = None
        self.initialized = False
        self.lite_mode = lite_mode
        
        if not GEMINI_AVAILABLE:
            logger.error("google-genai package not installed. Run: pip install google-genai")
            return
        
        if not self.api_key:
            logger.error("No Gemini API key provided!")
            logger.error("Set GEMINI_API_KEY environment variable or use --gemini-api-key flag")
            return
        
        try:
            # Initialize the new google.genai client
            logger.info(f"Initializing Gemini with API key: {self.api_key[:10]}...")
            self.client = genai.Client(api_key=self.api_key)
            # Use Gemini 2.0 Flash (latest)
            self.model_name = 'gemini-2.0-flash-exp'
            self.initialized = True
            logger.info(f"Gemini AI analyzer initialized successfully {'(lite mode)' if lite_mode else ''}")
        except Exception as e:
            logger.error(f"Failed to initialize Gemini: {e}")
            import traceback
            traceback.print_exc()
    
    def is_available(self):
        """Check if the analyzer is ready to use."""
        return self.initialized and hasattr(self, 'client') and self.client is not None
    
    def _safe_generate(self, prompt, max_tokens=2048):
        """Safely generate content with error handling and rate limiting."""
        global _last_request_time
        
        if not self.is_available():
            logger.error("Analyzer not available for generation")
            return None
        
        # Rate limiting for free tier
        elapsed = time.time() - _last_request_time
        if elapsed < GEMINI_RATE_LIMIT_DELAY:
            wait_time = GEMINI_RATE_LIMIT_DELAY - elapsed
            logger.info(f"Rate limiting: waiting {wait_time:.1f}s before next API call")
            time.sleep(wait_time)
        
        try:
            logger.info(f"Calling Gemini API (model: {self.model_name})...")
            _last_request_time = time.time()
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    max_output_tokens=max_tokens,
                    temperature=0.3,  # Lower temperature for more focused responses
                )
            )
            logger.info("Gemini API call successful")
            return response.text
        except Exception as e:
            error_msg = str(e).lower()
            logger.error(f"Gemini API error: {e}")
            if 'quota' in error_msg or 'rate' in error_msg or '429' in error_msg:
                logger.warning("Rate limit hit. Waiting 60 seconds before retry...")
                time.sleep(60)
                # Retry once
                try:
                    _last_request_time = time.time()
                    response = self.client.models.generate_content(
                        model=self.model_name,
                        contents=prompt,
                        config=types.GenerateContentConfig(
                            max_output_tokens=max_tokens,
                            temperature=0.3,
                        )
                    )
                    return response.text
                except Exception as retry_error:
                    logger.error(f"Retry failed: {retry_error}")
                    return None
            return None
    
    def analyze_vulnerabilities(self, vulnerabilities, target_domain):
        """
        Analyze discovered vulnerabilities and provide remediation advice.
        
        Args:
            vulnerabilities: List of vulnerability strings from nuclei output
            target_domain: The target domain being scanned
        
        Returns:
            AI-generated analysis with severity ratings and remediation steps
        """
        if not vulnerabilities:
            return "No vulnerabilities to analyze."
        
        # Limit to first 20 vulnerabilities to avoid token limits
        vuln_sample = vulnerabilities[:20]
        vuln_text = "\n".join(vuln_sample)
        
        prompt = f"""You are a cybersecurity expert analyzing vulnerability scan results for {target_domain}.

Analyze these vulnerabilities found by Nuclei scanner:

{vuln_text}

Provide a structured analysis with:
1. **Executive Summary** - Brief overview of the security posture
2. **Critical Findings** - Most severe issues requiring immediate attention
3. **Risk Assessment** - Overall risk level (Critical/High/Medium/Low)
4. **Remediation Priority List** - Ordered list of fixes by importance
5. **Specific Recommendations** - Technical steps to fix each vulnerability type

Be concise but thorough. Focus on actionable advice."""

        return self._safe_generate(prompt, max_tokens=3000)
    
    def analyze_secrets(self, secrets):
        """
        Analyze discovered secrets and classify their severity.
        
        Args:
            secrets: List of secret findings (dicts with type, value, source)
        
        Returns:
            AI analysis with severity classification and recommended actions
        """
        if not secrets:
            return "No secrets to analyze."
        
        # Redact actual secret values for safety
        redacted_secrets = []
        for secret in secrets[:15]:
            redacted = {
                'type': secret.get('type', 'Unknown'),
                'source': secret.get('source', 'Unknown'),
                'value_preview': secret.get('value', '')[:10] + '...' if secret.get('value') else 'N/A'
            }
            redacted_secrets.append(redacted)
        
        secrets_text = json.dumps(redacted_secrets, indent=2)
        
        prompt = f"""You are a security expert analyzing exposed secrets/credentials found during a security scan.

Discovered secrets (values redacted for safety):

{secrets_text}

Provide analysis with:
1. **Severity Classification** - Rate each secret type (Critical/High/Medium/Low)
2. **Potential Impact** - What could an attacker do with each type
3. **Immediate Actions** - Steps to take right now (rotate, revoke, etc.)
4. **Prevention Tips** - How to prevent future exposure
5. **Detection Recommendations** - How to monitor for misuse

Prioritize by potential damage."""

        return self._safe_generate(prompt, max_tokens=2000)
    
    def analyze_attack_surface(self, scan_results):
        """
        Provide a comprehensive analysis of the discovered attack surface.
        
        Args:
            scan_results: Dict containing various scan results
        
        Returns:
            AI-generated attack surface analysis
        """
        # Build a summary of findings
        summary = {
            'subdomains_count': len(scan_results.get('subdomains', [])),
            'live_hosts_count': len(scan_results.get('live_hosts', [])),
            'vulnerabilities_count': len(scan_results.get('vulnerabilities', [])),
            'api_endpoints_count': len(scan_results.get('api_endpoints', [])),
            'secrets_count': len(scan_results.get('secrets', [])),
            'parameters_count': len(scan_results.get('parameters', [])),
            'sample_subdomains': scan_results.get('subdomains', [])[:10],
            'sample_endpoints': scan_results.get('api_endpoints', [])[:10],
        }
        
        summary_text = json.dumps(summary, indent=2)
        
        prompt = f"""You are a penetration tester analyzing an organization's attack surface.

Scan Results Summary:
{summary_text}

Provide a strategic analysis:
1. **Attack Surface Overview** - Size and complexity assessment
2. **High-Value Targets** - Which assets are most attractive to attackers
3. **Attack Vectors** - Potential paths an attacker might take
4. **Security Gaps** - Areas that need immediate attention
5. **Hardening Recommendations** - Steps to reduce the attack surface
6. **Monitoring Suggestions** - What to watch for ongoing security

Think like an attacker but advise like a defender."""

        return self._safe_generate(prompt, max_tokens=2500)
    
    def generate_executive_report(self, target_domain, scan_results):
        """
        Generate an executive-level summary report.
        
        Args:
            target_domain: The scanned domain
            scan_results: Dict containing scan results
        
        Returns:
            Executive summary suitable for non-technical stakeholders
        """
        stats = {
            'target': target_domain,
            'subdomains': len(scan_results.get('subdomains', [])),
            'live_hosts': len(scan_results.get('live_hosts', [])),
            'vulnerabilities': len(scan_results.get('vulnerabilities', [])),
            'secrets_exposed': len(scan_results.get('secrets', [])),
            'api_endpoints': len(scan_results.get('api_endpoints', [])),
        }
        
        prompt = f"""Create an executive summary for a security assessment of {target_domain}.

Findings:
- Subdomains discovered: {stats['subdomains']}
- Live web services: {stats['live_hosts']}
- Vulnerabilities found: {stats['vulnerabilities']}
- Exposed secrets/credentials: {stats['secrets_exposed']}
- API endpoints discovered: {stats['api_endpoints']}

Write a professional executive summary (suitable for C-level executives) that includes:
1. **Overview** - One paragraph summary
2. **Risk Rating** - Overall security posture (Critical/High/Medium/Low/Good)
3. **Key Concerns** - Top 3 issues requiring attention
4. **Business Impact** - Potential consequences if not addressed
5. **Recommended Actions** - High-level steps to improve security
6. **Timeline** - Suggested prioritization (Immediate/Short-term/Long-term)

Keep it concise, non-technical, and focused on business risk."""

        return self._safe_generate(prompt, max_tokens=1500)
    
    def suggest_next_steps(self, scan_results):
        """
        Suggest next steps for further testing based on findings.
        
        Args:
            scan_results: Dict containing scan results
        
        Returns:
            AI-suggested next steps for deeper testing
        """
        findings = {
            'has_vulns': len(scan_results.get('vulnerabilities', [])) > 0,
            'has_secrets': len(scan_results.get('secrets', [])) > 0,
            'has_apis': len(scan_results.get('api_endpoints', [])) > 0,
            'has_params': len(scan_results.get('parameters', [])) > 0,
            'subdomain_count': len(scan_results.get('subdomains', [])),
        }
        
        prompt = f"""As a penetration testing expert, suggest next steps based on these ASM scan findings:

{json.dumps(findings, indent=2)}

Recommend:
1. **Manual Testing Priorities** - What to test manually first
2. **Additional Tools** - Specific tools for deeper analysis
3. **Exploitation Paths** - Safe ways to validate vulnerabilities
4. **Documentation Needs** - What to document for the report
5. **Out-of-Scope Considerations** - What might need additional authorization

Focus on practical, actionable next steps."""

        return self._safe_generate(prompt, max_tokens=1500)
    
    def quick_summary(self, target_domain, scan_results):
        """
        Generate a quick combined summary (for lite mode - single API call).
        
        Args:
            target_domain: The scanned domain
            scan_results: Dict containing scan results
        
        Returns:
            Combined analysis in one response
        """
        stats = {
            'target': target_domain,
            'subdomains': len(scan_results.get('subdomains', [])),
            'live_hosts': len(scan_results.get('live_hosts', [])),
            'vulnerabilities': len(scan_results.get('vulnerabilities', [])),
            'secrets_exposed': len(scan_results.get('secrets', [])),
            'api_endpoints': len(scan_results.get('api_endpoints', [])),
            'sample_vulns': scan_results.get('vulnerabilities', [])[:5],
        }
        
        prompt = f"""Analyze this security scan of {target_domain}:

Stats: {stats['subdomains']} subdomains, {stats['live_hosts']} live hosts, {stats['vulnerabilities']} vulnerabilities, {stats['secrets_exposed']} secrets, {stats['api_endpoints']} API endpoints

Sample vulnerabilities: {stats['sample_vulns'][:3] if stats['sample_vulns'] else 'None'}

Provide a brief security assessment:
1. Risk Level (Critical/High/Medium/Low)
2. Top 3 concerns
3. Priority fixes
4. Next steps

Be concise."""

        return self._safe_generate(prompt, max_tokens=1000)


def analyze_scan_with_ai(output_dir, api_key=None, lite_mode=True):
    """
    Run AI analysis on completed scan results.
    
    Args:
        output_dir: Path to the scan output directory
        api_key: Optional Gemini API key
        lite_mode: If True, makes fewer API calls (default for free tier)
    
    Returns:
        Dict containing all AI analyses
    """
    logger.info(f"Starting AI analysis for: {output_dir}")
    output_path = Path(output_dir)
    
    if not output_path.exists():
        logger.error(f"Output directory not found: {output_dir}")
        return None
    
    analyzer = GeminiAnalyzer(api_key, lite_mode=lite_mode)
    
    if not analyzer.is_available():
        logger.error("AI analyzer not available!")
        if not api_key and not os.environ.get('GEMINI_API_KEY'):
            logger.error("No API key found. Use --gemini-api-key or set GEMINI_API_KEY env variable")
        return None
    
    results = {}
    scan_data = {}
    
    # Load scan results
    files_to_load = {
        'subdomains': 'subdomains.txt',
        'live_hosts': 'live_hosts.txt',
        'vulnerabilities': 'vulnerabilities.txt',
        'api_endpoints': 'api_endpoints.txt',
    }
    
    for key, filename in files_to_load.items():
        file_path = output_path / filename
        if file_path.exists():
            with open(file_path, 'r') as f:
                scan_data[key] = [line.strip() for line in f if line.strip()]
        else:
            scan_data[key] = []
    
    # Load JSON files
    secrets_file = output_path / 'secrets_found.json'
    if secrets_file.exists():
        try:
            with open(secrets_file, 'r') as f:
                scan_data['secrets'] = json.load(f)
        except:
            scan_data['secrets'] = []
    else:
        scan_data['secrets'] = []
    
    params_file = output_path / 'discovered_params.json'
    if params_file.exists():
        try:
            with open(params_file, 'r') as f:
                params_data = json.load(f)
                unique_params = set()
                for url, params in params_data.items():
                    if isinstance(params, list):
                        unique_params.update(params)
                scan_data['parameters'] = list(unique_params)
        except:
            scan_data['parameters'] = []
    else:
        scan_data['parameters'] = []
    
    # Get target domain from directory name
    target_domain = output_path.name
    
    logger.info(f"Running AI analysis on scan results... {'(lite mode - fewer API calls)' if lite_mode else ''}")
    
    if lite_mode:
        # Lite mode: Single API call for quick summary (best for free tier)
        logger.info("Generating quick summary (1 API call)...")
        results['quick_summary'] = analyzer.quick_summary(target_domain, scan_data)
        
        # Only do detailed vuln analysis if there are vulnerabilities
        if scan_data.get('vulnerabilities') and len(scan_data['vulnerabilities']) > 0:
            logger.info("Analyzing vulnerabilities...")
            time.sleep(GEMINI_RATE_LIMIT_DELAY)  # Rate limit
            results['vulnerability_analysis'] = analyzer.analyze_vulnerabilities(
                scan_data['vulnerabilities'], target_domain
            )
    else:
        # Full mode: Multiple API calls (for paid tier)
        if scan_data.get('vulnerabilities'):
            logger.info("Analyzing vulnerabilities...")
            results['vulnerability_analysis'] = analyzer.analyze_vulnerabilities(
                scan_data['vulnerabilities'], target_domain
            )
        
        if scan_data.get('secrets'):
            logger.info("Analyzing secrets...")
            results['secrets_analysis'] = analyzer.analyze_secrets(scan_data['secrets'])
        
        logger.info("Generating attack surface analysis...")
        results['attack_surface_analysis'] = analyzer.analyze_attack_surface(scan_data)
        
        logger.info("Generating executive report...")
        results['executive_summary'] = analyzer.generate_executive_report(target_domain, scan_data)
        
        logger.info("Generating next steps...")
        results['next_steps'] = analyzer.suggest_next_steps(scan_data)
    
    # Save AI analysis to file
    ai_report_file = output_path / 'ai_analysis.md'
    with open(ai_report_file, 'w') as f:
        f.write(f"# AI-Powered Security Analysis: {target_domain}\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Mode:** {'Lite (Free Tier)' if lite_mode else 'Full Analysis'}\n\n")
        f.write("---\n\n")
        
        if results.get('quick_summary'):
            f.write("## Quick Security Summary\n\n")
            f.write(results['quick_summary'])
            f.write("\n\n---\n\n")
        
        if results.get('executive_summary'):
            f.write("## Executive Summary\n\n")
            f.write(results['executive_summary'])
            f.write("\n\n---\n\n")
        
        if results.get('vulnerability_analysis'):
            f.write("## Vulnerability Analysis\n\n")
            f.write(results['vulnerability_analysis'])
            f.write("\n\n---\n\n")
        
        if results.get('secrets_analysis'):
            f.write("## Secrets Analysis\n\n")
            f.write(results['secrets_analysis'])
            f.write("\n\n---\n\n")
        
        if results.get('attack_surface_analysis'):
            f.write("## Attack Surface Analysis\n\n")
            f.write(results['attack_surface_analysis'])
            f.write("\n\n---\n\n")
        
        if results.get('next_steps'):
            f.write("## Recommended Next Steps\n\n")
            f.write(results['next_steps'])
            f.write("\n\n")
        
        f.write("---\n")
        f.write("\n*Analysis generated by ASM Tool with Google Gemini AI*\n")
    
    logger.info(f"AI analysis saved to: {ai_report_file}")
    return results


# Standalone usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python ai_analysis.py <scan_output_directory> [api_key] [--full]")
        print("       Or set GEMINI_API_KEY environment variable")
        print("")
        print("Options:")
        print("  --full    Use full analysis mode (more API calls, for paid tier)")
        print("")
        print("Default is lite mode (1-2 API calls, safe for free tier)")
        sys.exit(1)
    
    scan_dir = sys.argv[1]
    api_key = None
    lite_mode = True
    
    for arg in sys.argv[2:]:
        if arg == '--full':
            lite_mode = False
        elif not arg.startswith('-'):
            api_key = arg
    
    # Setup logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    results = analyze_scan_with_ai(scan_dir, api_key, lite_mode=lite_mode)
    
    if results:
        print("\n✅ AI analysis complete!")
        print(f"Report saved to: {scan_dir}/ai_analysis.md")
    else:
        print("\n❌ AI analysis failed. Check your API key and dependencies.")
