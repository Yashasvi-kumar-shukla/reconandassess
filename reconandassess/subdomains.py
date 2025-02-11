import subprocess
import os

class sub:
       def run_subfinder(domain):
            print(f"[+] Running Subfinder for domain: {domain}...")
            subfinder_cmd = f"subfinder -d {domain} -o subdomains[{domain}].txt -v -t 50 -r 8.8.8.8 -timeout 30 -all"
            subprocess.run(subfinder_cmd, shell=True)
            output_file = f"subdomains[{domain}].txt"
            full_path = os.path.abspath(output_file)
            print(f"[+] URLs saved at: {full_path}")

       def run_gobuster(domain):
            print(f"[+] Running Gobuster for domain: {domain}...")
            #wordlist = input("Enter the path to the wordlist
            amass_cmd = f"gobuster dns -d {domain} -w subdomains-top1million-5000.txt -o gobuster_subdomains[{domain}].txt"
            process = subprocess.Popen(amass_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output_file = f"gobuster_subdomains[{domain}].txt"
            full_path = os.path.abspath(output_file)
            print(f"[+]  URLs saved at: {full_path}")
            
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
                output_file = f"all_subdomains[{domain}].txt"
                full_path = os.path.abspath(output_file)
                print(f"[+]  URLs saved at: {full_path}")
            else:
                print(f"[!] No subdomains found for {domain}. An empty file has been created to prevent errors.")
