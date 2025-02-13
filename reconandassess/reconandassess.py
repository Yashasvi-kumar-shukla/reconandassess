import subprocess
import os
import requests
import httpx
import asyncio
import re
import time
import threading
from wordpress import wordpress
from Nmap import nmap_scan
from subdomains import sub
from drup import drooper


def get_target_folder(target):
    folder = f"results/{target}"
    os.makedirs(folder, exist_ok=True)  # Ensure the directory exists
    return folder

def run_fuzzing(target):
    print(f"[+] Performing fuzzing on {target}...")
    folder = get_target_folder(target)
    output_file = f"{folder}/fuzzing_results[{target}].txt"
    fuzzing_cmd = f"ffuf -u https://{target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -r -o {output_file}"
    print(f"[+] Fuzzing completed. Results saved to 'fuzzing_results[{target}].txt'.")

def run_sqlmap(target):
    print(f"[+] Running SQLMap on {target}...")
    folder = get_target_folder(target)
    output_file = f"{folder}/sqlmap_results[{target}]"
    sqlmap_cmd = f"sqlmap -u {target} --batch --dbs --output-dir={output_file}"
    subprocess.run(sqlmap_cmd, shell=True)
    print(f"[+] SQLMap scan completed. Results saved in 'sqlmap_results[{target}]'.")

def run_xss_scan(target):
    print(f"[+] Running XSS scan on {target} with XSStrike...")
    folder = get_target_folder(target)
    output_file = f"{folder}/xss_results[{target}].txt"
    xss_cmd = f"python3 XSStrike/xsstrike.py -u https://{target} --crawl --blind"

    with open(output_file, "w") as file:
        subprocess.run(xss_cmd, shell=True, stdout=file, stderr=file)
    
    full_path = os.path.abspath(output_file)
    print(f"[+] URLs saved at: {full_path}")

def save_special_character_urls(target, urls):
    folder = get_target_folder(target)
    output_file = f"{folder}/special_urls[{target}].txt"
    special_urls = [url for url in urls if re.search(r'[\?\&\=\%]', url)]

    if special_urls:
        with open(output_file, "w") as file:
            file.write("\n".join(special_urls) + "\n")
        full_path = os.path.abspath(output_file)
        print(f"[+] Special character URLs saved at: {full_path}")
    else:
        print(f"[!] No special character URLs found for {target}.")
        
def run_wayback_urls(target):
    print(f"[+] Extracting Wayback Machine URLs for {target}...")
    folder = get_target_folder(target)
    output_file = f"{folder}/wayback_urls[{target}].txt"
    wayback_cmd = f"getallurls {target} "
    subprocess.run(wayback_cmd, shell=True)
    wayback_cmd = f"getallurls {target} > {folder}/wayback_urls[{target}].txt"
    subprocess.run(wayback_cmd, shell=True)
    full_path = os.path.abspath(output_file)
    print(f"[+] Wayback URLs saved at: {full_path}")

    # Detect URLs with special characters
    with open(output_file, "r") as file:
        urls = [line.strip() for line in file if line.strip()]
    save_special_character_urls(target, urls)

def run_subzy(target):
    print(f"[+] Checking for subdomain takeover on {target}...")
    folder = get_target_folder(target)
    output_file = f"{folder}/subzy_results[{target}].txt"
    subzy_cmd = f"go run ./main.go run --target {target}"
    subprocess.run(subzy_cmd, shell=True)
    subzy_cmd = f"go run ./main.go run --target {target} > {output_file}"
    subprocess.run(subzy_cmd, shell=True)
    full_path = os.path.abspath(output_file)
    print(f"[+] URLs saved at: {full_path}")



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
    folder = get_target_folder(target)
    domain = target if '.' in target else f"www.{target}"
    INPUT_FILE = f"{folder}/all_subdomains[{domain}].txt"
    OUTPUT_FILE = f"{folder}/live_subdomains[{domain}].txt"
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
    output_file = f"{folder}/live_subdomains[{domain}].txt"
    full_path = os.path.abspath(output_file)
    print(f"[+] Wayback URLs saved at: {full_path}")
    
    for live_site in live_sites:
        run_fuzzing(live_site)
        run_sqlmap(live_site)
        run_xss_scan(live_site)
        run_subzy(live_site)
        drooper.droopscan(live_site)



def main(target):
    folder = get_target_folder(target)
    nmap_scan.run_nmap(target)

    domain = target if '.' in target else f"www.{target}"
    sub.run_subfinder(domain)
    
    # Run Amass with timeout handling
    sub.run_gobuster(domain)  

    sub.combine_subdomains(domain)
    print(f"[+] Running Wayback URL extraction for {domain}...")
    run_wayback_urls(domain)

    with open(f"{folder}/all_subdomains[{domain}].txt", "r") as subdomain_file:
        subdomains = subdomain_file.readlines()
    for subdomain in subdomains:
        subdomain = subdomain.strip()
        print(f"Checking if {subdomain} uses WordPress...")
        wordpress.run_wordpress_recon(subdomain)
  
if __name__ == "__main__":
    targets = input("Enter target IPs or URLs (comma-separated): ")
    target_list = [t.strip() for t in targets.split(",") if t.strip()]
    for target in target_list:
        print(f"\n{'='*40}")
        print(f"[+] Running scans for target: {target}")
        print(f"{'='*40}\n")
        main(target)
        asyncio.run(livefinder(target))
