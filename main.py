import subprocess
import os
import argparse
import sys

def run_command(command):
    """Helper to run shell commands and handle errors."""
    try:
        # shell=True allows using pipes (|) in the command string
        result = subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[-] Error executing: {command}")
        # print(f"    Error details: {e.stderr}") # Uncomment for debugging
        return None

def module_discovery(target_domain):
    print(f"\n[+] --- Starting Phase 1: Subdomain Discovery for {target_domain} ---")
    
    # Define output filenames based on the target
    subs_file = f"{target_domain}_subs.txt"
    alive_file = f"{target_domain}_alive.txt"

    # 1. Run Subfinder
    print(f"[*] Running Subfinder...")
    # -silent: only output domains
    cmd_subfinder = f"subfinder -d {target_domain} -silent -o {subs_file}"
    run_command(cmd_subfinder)

    # Check if subfinder actually found anything
    if os.path.exists(subs_file) and os.path.getsize(subs_file) > 0:
        count = len(open(subs_file).readlines())
        print(f"[+] Found {count} subdomains.")
    else:
        print("[-] No subdomains found or tool failed. Exiting.")
        return

    # 2. Run HTTPX (Live Host Check)
    print(f"[*] Running HTTPX to check for live web servers...")
    
    # Using 'httpx-toolkit' as is common on Kali. 
    # If your Kali uses 'httpx', change the command below.
    cmd_httpx = f"cat {subs_file} | httpx-toolkit -silent -sc -title -o {alive_file}"
    run_command(cmd_httpx)

    if os.path.exists(alive_file) and os.path.getsize(alive_file) > 0:
        live_count = len(open(alive_file).readlines())
        print(f"[+] {live_count} live hosts saved to: {alive_file}")
    else:
        print("[-] No live hosts found.")

def main():
    # Setup Argument Parser
    parser = argparse.ArgumentParser(description="Basic ASM Recon Tool")
    parser.add_argument("-t", "--target", help="The target domain (e.g., example.com)", required=True)
    
    args = parser.parse_args()

    # Pass the argument to the discovery module
    module_discovery(args.target)

if __name__ == "__main__":
    main()