import requests
import subprocess


class wordpress:
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
	    
	
      def run_wpscan(subdomain,YOUR_API_KEY):
            print(f"[+] Running WPScan on {subdomain}...")
            wpscan_cmd = f"wpscan --url {subdomain} --enumerate vp --api-token {YOUR_API_KEY}"
            subprocess.run(wpscan_cmd, shell=True)

