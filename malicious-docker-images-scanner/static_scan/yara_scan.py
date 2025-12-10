import subprocess
import os

def scan_with_yara(image_name):
    """Extract Docker image and scan with YARA"""
    try:
        # Create paths
        tar_file = f'/tmp/{image_name.replace(":", "_")}.tar'
        extract_path = f'/tmp/{image_name.replace(":", "_")}_extracted'
        
        # 1. Export the image
        # ensure_image_exists in app.py handles the pulling, so we just have to save here
        if not os.path.exists(extract_path):
             print(f"[YARA] Extracting image {image_name}...")
             subprocess.run(['docker', 'save', image_name, '-o', tar_file], check=True, timeout=60)
             os.makedirs(extract_path, exist_ok=True)
             subprocess.run(['tar', '-xf', tar_file, '-C', extract_path], check=True)
        
        print(f"[YARA] Scanning extracted files...")
        
        # 2. Run YARA (Make sure there are NO [cite] tags here!check repeat,it happened last time time too)
        result = subprocess.run(
            ['yara', '-r', 'static_scan/malware_rules.yar', extract_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        # 3. Process results
        findings = []
        if result.stdout:
            findings = result.stdout.strip().split('\n')
        
        return {
            'status': 'success',
            'findings': findings,
            'detected': len(findings) > 0
        }
    except Exception as e:
        return {'status': 'error', 'message': str(e)}
