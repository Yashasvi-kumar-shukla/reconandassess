import subprocess
import os

class sub:
       def get_target_folder(target):
            folder = f"results/{target}"
            os.makedirs(folder, exist_ok=True)  # Ensure the directory exists
            return folder
            
       def run_subfinder(domain):
            print(f"[+] Running Subfinder for domain: {domain}...")
            folder = sub.get_target_folder(domain)
            output_file = f"{folder}/subdomains[{domain}].txt"
            subfinder_cmd = f"subfinder -d {domain} -o {output_file} -v -t 50 -r 8.8.8.8 -timeout 30 -all"
            subprocess.run(subfinder_cmd, shell=True)
            full_path = os.path.abspath(output_file)
            print(f"[+] URLs saved at: {full_path}")

       def run_gobuster(domain):
            print(f"[+] Running Gobuster for domain: {domain}...")
            #wordlist = input("Enter the path to the wordlist
            folder = sub.get_target_folder(domain)
            output_file = f"{folder}/gobuster_subdomains[{domain}].txt"
            amass_cmd = f"gobuster dns -d {domain} -w subdomains-top1million-5000.txt -o {output_file}"
            process = subprocess.Popen(amass_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            full_path = os.path.abspath(output_file)
            print(f"[+]  URLs saved at: {full_path}")
            
       def combine_subdomains(domain):
            print(f"[+] Combining subdomains from Subfinder and Gobuster for {domain}...")
            folder = sub.get_target_folder(domain)
            subfinder_file = f"{folder}/subdomains[{domain}].txt"
            gobuster_file = f"{folder}/gobuster_subdomains[{domain}].txt"
            all_subdomains_file = f"{folder}/all_subdomains[{domain}].txt"
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
                output_file = f"{folder}/all_subdomains[{domain}].txt"
                full_path = os.path.abspath(output_file)
                print(f"[+]  URLs saved at: {full_path}")
            else:
                print(f"[!] No subdomains found for {domain}. An empty file has been created to prevent errors.")
