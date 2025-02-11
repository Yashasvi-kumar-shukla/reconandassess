import subprocess
import os

class nmap_scan:
	def run_nmap(target):
	    print(f"[+] Running Nmap scan on {target}...")
	    nmap_cmd = f"nmap -T3 -A -v {target} -oN nmap_scan_results[{target}].txt"
	    subprocess.run(nmap_cmd, shell=True)
	    output_file = f"nmap_scan_results[{target}].txt"
	    full_path = os.path.abspath(output_file)
	    print(f"[+] Nmap scan completed. Results saved at: {full_path}")
