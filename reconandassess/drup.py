import subprocess
import os

class drooper:
	def get_target_folder(target):
		folder = f"results/{target}"
		os.makedirs(folder, exist_ok=True)  # Ensure the directory exists
		return folder
		
	def droopscan(target):
		print(f"[+] Performing Drupal enumeration for {target}...")
		folder = drooper.get_target_folder(target)
		output_file = f"{folder}/Drupal[{target}].txt"
		wayback_cmd = f"drupwn --mode enum --target https://{target}"
		subprocess.run(wayback_cmd, shell=True)
		wayback_cmd = f"drupwn --mode enum --target https://{target} > {output_file}"
		subprocess.run(wayback_cmd, shell=True)
		full_path = os.path.abspath(output_file)
		print(f"[+]  Drupal Output saved at: {full_path}")
		
