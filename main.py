import subprocess
import os

def run_command(command):
    """Helper to run shell commands and handle errors."""
    try:
        # We use shell=True here for simplicity in chaining commands, 
        # but in production code, lists are safer.
        result = subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[-] Error executing: {command}")
        print(f"    Error details: {e.stderr}")
        return None

def module_discovery(target_domain):
    print(f"\n[+] --- Starting Phase 1: Subdomain Discovery for {target_domain} ---")
    
    # Output files
    subs_file = f"{target_domain}_subs.txt"
    alive_file = f"{target_domain}_alive.txt"

    # 1. Run Subfinder
    # -silent: only output domains
    print(f"[*] Running Subfinder...")
    cmd_subfinder = f"subfinder -d {target_domain} -silent -o {subs_file}"
    run_command(cmd_subfinder)

    if os.path.exists(subs_file):
        count = len(open(subs_file).readlines())
        print(f"[+] Found {count} subdomains.")
    else:
        print("[-] No subdomains found. Exiting.")
        return

    # 2. Run HTTPX (Live Host Check)
    # We take the list of subdomains and check which ones have web servers
    # -sc: show status code
    # -title: show page title (useful for manual review)
    print(f"[*] Running HTTPX to check for live web servers...")
    
    # Note: In Kali, the binary is sometimes 'httpx-toolkit' or just 'httpx'
    # Check which one works in your terminal. We will use 'httpx-toolkit' which is common in Kali repo.
    cmd_httpx = f"cat {subs_file} | httpx-toolkit -silent -sc -title -o {alive_file}"
    run_command(cmd_httpx)

    if os.path.exists(alive_file):
        print(f"[+] Live hosts saved to: {alive_file}")
        print("[+] Preview of live hosts:")
        os.system(f"head -n 5 {alive_file}")
    else:
        print("[-] No live hosts found.")

if __name__ == "__main__":
    # Change this to your target
    TARGET = "google.com"  # Example target (use your own authorized domain)
    module_discovery(TARGET)