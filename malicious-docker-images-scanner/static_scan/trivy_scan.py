import subprocess
import json

def scan_with_trivy(image_name):
    """Scan Docker image with Trivy and return JSON-safe result."""
    try:
        # Run Trivy in JSON mode
        result = subprocess.run(
            ['trivy', 'image', '--format', 'json', image_name],
            capture_output=True,
            text=True,
            timeout=120
        )

        # If Trivy failed, don't try to parse JSON
        if result.returncode != 0:
            # Return error instead of crashing JSON parser
            message = result.stderr.strip() or result.stdout.strip() or "Unknown Trivy error"
            return {'status': 'error', 'message': message}

        # If output is empty, return safe error
        if not result.stdout.strip():
            return {'status': 'error', 'message': 'Trivy returned empty output'}

        # Parse JSON safely
        data = json.loads(result.stdout)
        return {'status': 'success', 'data': data}

    except json.JSONDecodeError:
        return {'status': 'error', 'message': 'Failed to parse Trivy JSON output'}
    except subprocess.TimeoutExpired:
        return {'status': 'error', 'message': 'Trivy scan timed out'}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}


