import os

def check_falco_alerts():
    """to check Falco runtime alerts"""
    try:
        log_file = '/var/log/falco.log'
        if not os.path.exists(log_file):
            return {'status': 'warning', 'message': 'Falco not installed or logs not available'}
        
        with open(log_file, 'r') as f:
            lines = f.readlines()
        
        alerts = lines[-20:] if len(lines) > 20 else lines
        return {'status': 'success', 'alert_count': len(alerts), 'alerts': alerts}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}
