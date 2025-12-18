from flask import Flask, render_template, request
import subprocess
import os
import shutil
import time

# --- Import the Scanners ---
from static_scan.trivy_scan import scan_with_trivy
from static_scan.yara_scan import scan_with_yara
from static_scan.clamav_scan import scan_with_clamav
from dynamic_scan.falco_monitor import check_falco_alerts
from ml_model.risk_aggregator import calculate_risk_score

app = Flask(name, template_folder='templates', static_folder='static')


def ensure_image_exists(image_name):
    """
    Checks if an image exists locally.
    If not, it automatically pulls it from Docker Hub.
    """
    try:
        # 1. For checking if an image exists locally using 'docker inspect'
        subprocess.run(
            ['docker', 'image', 'inspect', image_name],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return True

    except subprocess.CalledProcessError:
        # 2. If an image is not found, try PULL it again
        print(f"[*] Image '{image_name}' not found locally. Auto-pulling from Docker Hub...")
        try:
            subprocess.run(['docker', 'pull', image_name], check=True)
            print(f"[*] Successfully pulled {image_name}")
            return True
        except subprocess.CalledProcessError:
            print(f"[!] Failed to pull {image_name}. It might not exist or is private.")
            return False


def run_dynamic_container(image_name):
    """
    Starts a temporary container for Falco dynamic analysis.
    Returns the container name/ID if successful, else None.
    """
    container_name = f"scan_test_{int(time.time())}"
    try:
        subprocess.run(
            ['docker', 'run', '-d', '--rm', '--name', container_name, image_name],
            check=True
        )
        # Give the entrypoint a few seconds to execute suspicious behaviour
        time.sleep(5)
        return container_name
    except Exception as e:
        print(f"[!] Failed to start dynamic container: {e}")
        return None


def stop_container(container_name):
    """
    Stops the temporary dynamic-analysis container (if it exists).
    """
    if container_name:
        subprocess.run(['docker', 'stop', container_name],
                       stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)


@app.route('/', methods=['GET', 'POST'])
def index():
    results = None
    error = None

    if request.method == 'POST':
        image_name = request.form.get('image_name', '').strip()

        if not image_name:
            error = 'Please enter a Docker image name (e.g., alpine:latest)'
            return render_template('index.html', error=error)

        # Allow users to type "alpine latest" and normalize to "alpine:latest"
        if ' ' in image_name:
            image_name = image_name.replace(' ', ':')

        try:
            print(f"
{'='*60}")
            print(f"🔍 STARTING SCAN FOR: {image_name}")
            print(f"{'='*60}
")

            # --- Counter-check for image: AUTO-PULL CHECK ---
            if not ensure_image_exists(image_name):
                error = (
                    f"Could not find or pull image '{image_name}'. "
                    f"Check spelling or internet connection."
                )
                return render_template('index.html', error=error)

            # --- STEP 1: Trivy Scan ---
            print("[1/4] Running Trivy vulnerability scan...")
            trivy_result = scan_with_trivy(image_name)

            # --- STEP 2: YARA Scan ---
            print("[2/4] Running YARA malware detection...")
            yara_result = scan_with_yara(image_name)

            # --- STEP 3: ClamAV Scan ---
            print("[3/4] Running ClamAV antivirus scan...")
            clamav_result = scan_with_clamav(image_name)
            
            # --- STEP 4: Falco ---
            print("[4/4] Checking Falco runtime alerts...")
            # Start a short‑lived container so Falco can observe runtime behaviour
            container_id = run_dynamic_container(image_name)
            falco_result = check_falco_alerts(image_name=image_name,
                                              container_id=container_id)
            stop_container(container_id)

            # --- STEP 5: Risk Calculation tab---
            print("
[*] Aggregating results and calculating risk...")
            risk_assessment = calculate_risk_score(
                trivy_result,
                yara_result,
                clamav_result,
                falco_result
            )

            results = {
                'image_name': image_name,
                'trivy': trivy_result,
                'yara': yara_result,
                'clamav': clamav_result,
                'falco': falco_result,
                'risk': risk_assessment
            }

            print(f"✅ SCAN COMPLETE - Final Risk Level: {risk_assessment['risk_level']}")
            print(f"{'='*60}
")

            # Optional: clean up any temporary filesystem artefacts if you export images
            extract_path = f"/tmp/{image_name.replace(':', '_')}_extracted"
            tar_path = f"/tmp/{image_name.replace(':', '_')}.tar"
            if os.path.exists(extract_path):
                shutil.rmtree(extract_path)
            if os.path.exists(tar_path):
                os.remove(tar_path)

        except Exception as e:
            print(f"❌ [CRITICAL ERROR] {str(e)}")
            error = f"System Error: {str(e)}"

    return render_template('index.html', results=results, error=error)


if name == 'main':
    app.run(debug=True, host='127.0.0.1', port=5000)
