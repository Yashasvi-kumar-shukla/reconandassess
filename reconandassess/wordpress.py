import requests
import os
import re

class wordpress:
        def get_target_folder(target):
           folder = f"results/wordpress_sites/{target}"
           os.makedirs(folder, exist_ok=True)
           return folder

        def save_results(target, filename, data):
            folder = get_target_folder(target)
            file_path = f"{folder}/{filename}"
	    
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
            headers_detected = False
            meta_detected = False
	    
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
                for header in response.headers:
                    if "wordpress" in response.headers.get(header, "").lower():
                        print(f"[✓] WordPress detected in headers: {header} -> {response.headers[header]}")
                        headers_detected = True
                        break
            except requests.exceptions.RequestException:
                pass

	    # Check Meta Tags
            try:
                response = session.get(url, timeout=5)
                if 'meta name="generator" content="WordPress' in response.text:
                    print(f"[✓] WordPress meta tag detected in {url}")
                    meta_detected = True
            except requests.exceptions.RequestException:
                pass

            if found or headers_detected or meta_detected:
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
            file_path = f"{folder}/wordpress_sites.txt"

            with open(file_path, "a") as file:
                file.write(url + "\n")

            print(f"[+] WordPress site saved in: {os.path.abspath(file_path)}")

	# ---------------------- Run WordPress Recon & Security Checks ----------------------
        def run_wordpress_recon(target):
            target = "https://"+target
            if wordpress.check_wordpress(target):
                wordpress.save_wordpress_url(target)
                wordpress.enumerate_plugins(target)
                wordpress.enumerate_themes(target)
                wordpress.check_xmlrpc(target)
                wordpress.check_debug_log(target)
                wordpress.check_users(target)
            else:
                print(f"[-] {target} is not a WordPress site.")
