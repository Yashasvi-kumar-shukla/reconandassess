import subprocess
import os
import requests
import httpx
import asyncio
import re
import time
import threading

def check_wordpress(url, timeout=10):  # Set a timeout to avoid stalling
    print(f"[+] Checking if {url} uses WordPress...")
    domain = "https://" + url
    try:
        wp_paths = ["/wp-login.php", "/wp-admin", "/wp-content/", "/wp-includes/"]
        
        for path in wp_paths:
            try:
                response = requests.get(domain + path, timeout=timeout)
                if response.status_code == 200:
                    print(f"[+] WordPress detected at {url}{path}")
                    return True
            except requests.exceptions.RequestException:
                continue  # Skip to next check

        # Check for WordPress-specific HTTP headers
        try:
            response = requests.get(domain, timeout=timeout)
            if 'X-Powered-By' in response.headers and 'WordPress' in response.headers['X-Powered-By']:
                print(f"[+] WordPress detected in HTTP headers.")
                return True
        except requests.exceptions.RequestException:
            pass

    except Exception as e:
        print(f"[-] Error during WordPress detection: {e}")

    print("[-] WordPress not detected.")
    return False

def save_wordpress_url(subdomain,domain):
    with open(f"wordpress_sites[{domain}].txt", "a") as file:
        file.write(subdomain + "\n")
    print(f"[+] WordPress site saved: {subdomain}")

def run_nmap(target):
    print(f"[+] Running Nmap scan on {target}...")
    nmap_cmd = f"nmap -T3 -A -v {target} -oN nmap_scan_results[{target}].txt"
    subprocess.run(nmap_cmd, shell=True)
    print(f"[+] Nmap scan completed. Results saved to 'nmap_scan_results[{target}].txt'.")

def run_subfinder(domain):
    print(f"[+] Running Subfinder for domain: {domain}...")
    subfinder_cmd = f"subfinder -d {domain} -o subdomains[{domain}].txt -v -t 50 -r 8.8.8.8 -timeout 30 -all"
    subprocess.run(subfinder_cmd, shell=True)
    print(f"[+] Subfinder completed. Results saved to 'subdomains[{domain}].txt'.")

def run_amass(domain, timeout=300):
    print(f"[+] Running Gobuster for domain: {domain}...")
    #wordlist = input("Enter the path to the wordlist

    amass_cmd = f"gobuster dns -d {domain} -w subdomains-top1million-5000.txt -o gobuster_subdomains[{domain}].txt"
    
    process = subprocess.Popen(amass_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print(f"[+] Subdomain saved in gobuster_subdomains[{domain}].txt")
    
def combine_subdomains(domain):
    print(f"[+] Combining subdomains from Subfinder and Gobuster for {domain}...")

    subfinder_file = f"subdomains[{domain}].txt"
    gobuster_file = f"gobuster_subdomains[{domain}].txt"
    all_subdomains_file = f"all_subdomains[{domain}].txt"

    subdomains = set()

    if os.path.exists(subfinder_file):
        with open(subfinder_file, "r") as sf:
            subdomains.update(line.strip() for line in sf if line.strip())

    if os.path.exists(gobuster_file):
        with open(gobuster_file, "r") as gf:
            subdomains.update(line.strip() for line in gf if line.strip())

    # Ensure the file is created even if no subdomains were found
    with open(all_subdomains_file, "w") as out:
        out.writelines(f"{sub}\n" for sub in subdomains)

    if subdomains:
        print(f"[+] Combined subdomains saved to '{all_subdomains_file}'.")
    else:
        print(f"[!] No subdomains found for {domain}. An empty file has been created to prevent errors.")


def clean_subdomain(subdomain):
    subdomain = subdomain.strip()
    return subdomain if re.match(r"^[a-zA-Z0-9.-]+$", subdomain) else None

async def check_httpx(subdomain):
    urls = [f"https://{subdomain}", f"http://{subdomain}"]  # Try both HTTP and HTTPS
    async with httpx.AsyncClient(follow_redirects=True, timeout=5, verify=False) as client:
        for url in urls:
            try:
                response = await client.get(url)
                if response.status_code < 400:
                    return subdomain  # Return live subdomain
            except httpx.RequestError:
                pass
    return None

def check_httprobe(subdomains):
    try:
        result = subprocess.run(
            ["httprobe", "-c", "50"],
            input="\n".join(subdomains),
            text=True,
            capture_output=True
        )
        return set(result.stdout.strip().split("\n"))
    except FileNotFoundError:
        print("[!] httprobe is not installed or not in PATH.")
        return set()


async def livefinder(target):
    domain = target if '.' in target else f"www.{target}"
    INPUT_FILE = f"all_subdomains[{domain}].txt"
    OUTPUT_FILE = f"live_subdomains[{domain}].txt"
    print("[+] Loading subdomains...")
    
    with open(INPUT_FILE, "r") as file:
        subdomains = [clean_subdomain(line) for line in file if clean_subdomain(line)]
    
    print(f"[+] Checking {len(subdomains)} subdomains with httpx...")
    httpx_results = await asyncio.gather(*[check_httpx(sub) for sub in subdomains])
    live_httpx = {sub for sub in httpx_results if sub}
    
    print("[+] Checking subdomains with httprobe...")
    live_httprobe = check_httprobe(subdomains)
    
    # Combine results from both tools
    live_sites = live_httpx.union(live_httprobe)
    
    print(f"[+] Found {len(live_sites)} live subdomains!")
    
    with open(OUTPUT_FILE, "w") as file:
        file.write("\n".join(live_sites) + "\n")
    
    print(f"[+] Live subdomains saved to {OUTPUT_FILE}")


def run_wpscan(subdomain,YOUR_API_KEY):
    print(f"[+] Running WPScan on {subdomain}...")
    wpscan_cmd = f"wpscan --url {subdomain} --enumerate vp --api-token {YOUR_API_KEY}"
    subprocess.run(wpscan_cmd, shell=True)

def main(target):
    run_nmap(target)

    domain = target if '.' in target else f"www.{target}"
    run_subfinder(domain)
    
    # Run Amass with timeout handling
    run_amass(domain, timeout=300)  

    combine_subdomains(domain)

    with open(f"all_subdomains[{domain}].txt", "r") as subdomain_file:
        subdomains = subdomain_file.readlines()
    YOUR_API_KEY = input("Enter your WPScan API key: ").strip()
    for subdomain in subdomains:
        subdomain = subdomain.strip()
        print(f"Checking if {subdomain} uses WordPress...")
        
        if check_wordpress(subdomain):
           save_wordpress_url(subdomain,domain)
           run_wpscan(subdomain,YOUR_API_KEY)
        else:
            print(f"WordPress is not used on {subdomain}")

if __name__ == "__main__":
    targets = input("Enter target IPs or URLs (comma-separated): ")
    target_list = [t.strip() for t in targets.split(",") if t.strip()]
    for target in target_list:
        print(f"\n{'='*40}")
        print(f"[+] Running scans for target: {target}")
        print(f"{'='*40}\n")
        main(target)
        asyncio.run(livefinder(target))
