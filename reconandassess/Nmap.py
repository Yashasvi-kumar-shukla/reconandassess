import subprocess
import os

class nmap_scan:
        def get_target_folder(target):
            folder = f"results/{target}"
            os.makedirs(folder, exist_ok=True)  # Ensure the directory exists
            return folder
            
        def run_nmap(target):
            print(f"[+] Running Nmap scan on {target}...")
            folder = nmap_scan.get_target_folder(target)
            output_file = f"{folder}/nmap_scan_results.txt"
            nmap_cmd = f"nmap -T3 -A -v {target} -oN {output_file}"
            subprocess.run(nmap_cmd, shell=True)
            full_path = os.path.abspath(output_file)
            print(f"[+] Nmap scan completed. Results saved at: {full_path}")
