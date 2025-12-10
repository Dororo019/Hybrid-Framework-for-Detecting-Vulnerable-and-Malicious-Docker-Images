import subprocess
import os

def scan_with_clamav(image_name):
    """Scan extracted Docker image with ClamAV"""
    try:
        # Define paths (Same naming convention as YARA)
        tar_file = f'/tmp/{image_name.replace(":", "_")}.tar'
        extract_path = f'/tmp/{image_name.replace(":", "_")}_extracted'
        
        # 1. Check if image is already extracted (by YARA?)
        if not os.path.exists(extract_path):
            print(f"[ClamAV] Image not found locally. Extracting {image_name}...")
            
            # Save and Extract (Backup logic if YARA didn't run)
            subprocess.run(['docker', 'save', image_name, '-o', tar_file], check=True, timeout=60)
            os.makedirs(extract_path, exist_ok=True)
            subprocess.run(['tar', '-xf', tar_file, '-C', extract_path], check=True)
            # os.remove(tar_file) # Optional cleanup
        else:
            print(f"[ClamAV] Using existing extracted files at {extract_path}...")

        print(f"[ClamAV] Scanning files for viruses...")
        
        # 2. Run ClamScan
        # -r: Recursive (scan all subfolders)
        # -i: Infected only (only print infected files)
        # --no-summary: Keep output clean
        result = subprocess.run(
            ['clamscan', '-r', '-i', extract_path],
            capture_output=True,
            text=True,
            timeout=120
        )
        
        # 3. Analyze Output
        output = result.stdout.strip()
        is_infected = "FOUND" in output
        
        return {
            'status': 'success',
            'output': output if output else "No threats found",
            'infected': is_infected
        }

    except Exception as e:
        print(f"[ClamAV Error] {e}")
        return {'status': 'error', 'message': str(e)}
