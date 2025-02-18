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
    
def run_subfinder(domain):
    print(f"[+] Running Subfinder for domain: {domain}...")
    folder = get_target_folder(domain)
    output_file = f"{folder}/subdomains[{domain}].txt"
    subfinder_cmd = f"subfinder -d {domain} -o {output_file} -v -t 50 -r 8.8.8.8 -timeout 30 -all"
    
    try:
        subprocess.run(subfinder_cmd, shell=True, check=True)
        full_path = os.path.abspath(output_file)
        print(f"[+] URLs saved at: {full_path}")
    except subprocess.CalledProcessError:
        print(f"[!] Error running Subfinder for {domain}. Please check if Subfinder is installed.")

def run_gobuster(domain):
    print(f"[+] Running Gobuster for domain: {domain}...")
    folder = get_target_folder(domain)
    output_file = f"{folder}/gobuster_subdomains[{domain}].txt"
    gobuster_cmd = f"gobuster dns -d {domain} -w subdomains-top1million-5000.txt -o {output_file}"
    
    try:
        process = subprocess.Popen(gobuster_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.communicate()  # Wait for process to complete
        full_path = os.path.abspath(output_file)
        print(f"[+] URLs saved at: {full_path}")
    except Exception as e:
        print(f"[!] Error running Gobuster: {e}")

def combine_subdomains(domain):
    print(f"[+] Combining subdomains from Subfinder and Gobuster for {domain}...")
    folder = get_target_folder(domain)
    subfinder_file = f"{folder}/subdomains[{domain}].txt"
    gobuster_file = f"{folder}/gobuster_subdomains[{domain}].txt"
    all_subdomains_file = f"{folder}/all_subdomains[{domain}].txt"
    
    subdomains = set()
    
    # Read Subfinder results
    if os.path.exists(subfinder_file):
        with open(subfinder_file, "r") as sf:
            subdomains.update(line.strip() for line in sf if line.strip())

    # Read Gobuster results
    if os.path.exists(gobuster_file):
        with open(gobuster_file, "r") as gf:
            subdomains.update(line.strip() for line in gf if line.strip())

    # Write combined subdomains to file
    with open(all_subdomains_file, "w") as out:
        out.writelines(f"{sub}\n" for sub in subdomains)

    if subdomains:
        full_path = os.path.abspath(all_subdomains_file)
        print(f"[+] Combined subdomains saved at: {full_path}")
    else:
        print(f"[!] No subdomains found for {domain}. An empty file has been created to prevent errors.")
    

def droopscan(target):
    print(f"[+] Performing Drupal enumeration for {target}...")
    folder = get_target_folder(target)
    output_file = f"{folder}/Drupal[{target}].txt"
    wayback_cmd = f"drupwn --mode enum --target https://{target} > {output_file}"
    subprocess.run(wayback_cmd, shell=True)
    subprocess.run(f"cat {output_file}", shell=True)
    full_path = os.path.abspath(output_file)
    print(f"[+]  Drupal Output saved at: {full_path}")

def save_results(target, filename, data):
    folder = get_target_folder(target)
    file_path = os.path.join(folder, filename)
    
    with open(file_path, "w") as file:
        file.write(data)
    
    print(f"[+] Results saved at: {os.path.abspath(file_path)}")

# ---------------------- WordPress Detection ----------------------
def check_wordpress(url):
    print(f"[+] Checking if {url} uses WordPress...")
    
    wp_indicators = [
        "/wp-login.php",
        "/wp-admin/",
        "/wp-content/",
        "/wp-includes/",
        "/feed/",
    ]
    
    session = requests.Session()
    found = False

    for path in wp_indicators:
        try:
            response = session.get(url + path, timeout=5)
            if response.status_code == 200:
                print(f"[✓] WordPress detected at {url}{path}")
                found = True
        except requests.exceptions.RequestException:
            continue

    # Check HTTP Headers
    try:
        response = session.get(url, timeout=5)
        for header, value in response.headers.items():
            if "wordpress" in value.lower():
                print(f"[✓] WordPress detected in headers: {header} -> {value}")
                found = True
                break
    except requests.exceptions.RequestException:
        pass

    # Check Meta Tags
    try:
        if 'meta name="generator" content="WordPress' in response.text:
            print(f"[✓] WordPress meta tag detected in {url}")
            found = True
    except requests.exceptions.RequestException:
        pass

    if found:
        return True
    else:
        print(f"[-] No WordPress indicators found on {url}.")
        return False

# ---------------------- WordPress Security Checks ----------------------
def enumerate_plugins(target):
    print(f"[+] Enumerating plugins for {target}...")
    plugin_list = ["akismet", "jetpack", "woocommerce", "yoast-seo", "wordfence"]
    
    detected_plugins = []
    for plugin in plugin_list:
        url = f"{target}/wp-content/plugins/{plugin}/"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                print(f"[✓] Found plugin: {plugin}")
                detected_plugins.append(plugin)
        except requests.exceptions.RequestException:
            continue
    
    if detected_plugins:
        save_results(target, "plugins.txt", "\n".join(detected_plugins))
    else:
        print(f"[-] No common plugins detected for {target}.")

def enumerate_themes(target):
    print(f"[+] Enumerating themes for {target}...")
    theme_list = ["twentytwentyone", "astra", "generatepress", "oceanwp", "divi"]
    
    detected_themes = []
    for theme in theme_list:
        url = f"{target}/wp-content/themes/{theme}/"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                print(f"[✓] Found theme: {theme}")
                detected_themes.append(theme)
        except requests.exceptions.RequestException:
            continue
    
    if detected_themes:
        save_results(target, "themes.txt", "\n".join(detected_themes))
    else:
        print(f"[-] No common themes detected for {target}.")

def check_xmlrpc(target):
    print(f"[+] Checking for XML-RPC vulnerabilities on {target}...")
    xmlrpc_url = f"{target}/xmlrpc.php"
    
    try:
        response = requests.post(xmlrpc_url, data='<methodCall><methodName>system.listMethods</methodName></methodCall>', timeout=5)
        if response.status_code == 200 and "system.listMethods" in response.text:
            print(f"[✓] XML-RPC is enabled and vulnerable at {xmlrpc_url}")
            save_results(target, "xmlrpc.txt", "XML-RPC is enabled and potentially vulnerable.")
        else:
            print(f"[-] XML-RPC does not seem vulnerable.")
    except requests.exceptions.RequestException:
        print(f"[-] Failed to connect to XML-RPC on {target}.")

def check_debug_log(target):
    print(f"[+] Checking for debug log exposure on {target}...")
    debug_log_url = f"{target}/wp-content/debug.log"
    
    try:
        response = requests.get(debug_log_url, timeout=5)
        if response.status_code == 200 and "PHP" in response.text:
            print(f"[✓] Debug log found at {debug_log_url}")
            save_results(target, "debug_log.txt", response.text)
        else:
            print(f"[-] No debug log found.")
    except requests.exceptions.RequestException:
        print(f"[-] Failed to check debug log.")

def check_users(target):
    print(f"[+] Enumerating users for {target}...")
    user_list = []
    
    for user_id in range(1, 5):
        url = f"{target}/?author={user_id}"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200 and "/author/" in response.url:
                username = response.url.split("/author/")[-1].strip("/")
                print(f"[✓] Found user: {username}")
                user_list.append(username)
        except requests.exceptions.RequestException:
            continue

    if user_list:
        save_results(target, "users.txt", "\n".join(user_list))
    else:
        print(f"[-] No users found.")

# ---------------------- Save WordPress URLs ----------------------
def save_wordpress_url(url):
    folder = "results/wordpress_sites"
    os.makedirs(folder, exist_ok=True)
    file_path = os.path.join(folder, "wordpress_sites.txt")

    with open(file_path, "a") as file:
        file.write(url + "\n")

    print(f"[+] WordPress site saved in: {os.path.abspath(file_path)}")

# ---------------------- Run WordPress Recon & Security Checks ----------------------
def run_wordpress_recon(target):
    target = "https://" + target if not target.startswith("http") else target
    if check_wordpress(target):
        save_wordpress_url(target)
        enumerate_plugins(target)
        enumerate_themes(target)
        check_xmlrpc(target)
        check_debug_log(target)
        check_users(target)
    else:
        print(f"[-] {target} is not a WordPress site.")
    
def run_nmap(target):
    print(f"[+] Running Nmap scan on {target}...")
    folder = get_target_folder(target)
    output_file = f"{folder}/nmap_scan_results.txt"
    nmap_cmd = f"nmap -T3 -A -v {target} -oN {output_file}"
    subprocess.run(nmap_cmd, shell=True)
    full_path = os.path.abspath(output_file)
    print(f"[+] Nmap scan completed. Results saved at: {full_path}")

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
    subzy_cmd = f"go run ./main.go run --target {target} > {output_file}"
    subprocess.run(subzy_cmd, shell=True)
    subprocess.run(f"cat {output_file}", shell=True)
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
        droopscan(live_site)



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
        run_wordpress_recon(subdomain)
  
if __name__ == "__main__":
    targets = input("Enter target IPs or URLs (comma-separated): ")
    target_list = [t.strip() for t in targets.split(",") if t.strip()]
    for target in target_list:
        print(f"\n{'='*40}")
        print(f"[+] Running scans for target: {target}")
        print(f"{'='*40}\n")
        main(target)
        asyncio.run(livefinder(target))
