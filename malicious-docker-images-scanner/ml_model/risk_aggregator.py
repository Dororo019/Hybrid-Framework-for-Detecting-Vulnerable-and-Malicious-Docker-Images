def calculate_risk_score(trivy_result, yara_result, clamav_result, falco_result):
    """
     All scanner outputs are combined into:
    1->risk_score (0 to 100)
    2-> risk_level (LOW, MEDIUM, HIGH, CRITICAL)
    3-> findings (list of strings for UI)
    4-> high_priority (list of strings: critical/high issues only)
    """

    score = 0
    findings = []
    high_priority = []

    # -------- TRIVY: vulnerabilities (CVEs) --------
    if trivy_result.get('status') == 'success':
        data = trivy_result.get('data', {})
        total_vulns = 0
        critical = 0
        high = 0

        try:
            if 'Results' in data:
                for r in data['Results']:
                    vulns = r.get('Vulnerabilities', []) or []
                    total_vulns += len(vulns)
                    critical += len([v for v in vulns if v.get('Severity') == 'CRITICAL'])
                    high += len([v for v in vulns if v.get('Severity') == 'HIGH'])

            # scoring: each CRITICAL adds 10, each HIGH adds 5 (cap to avoid 1000)
            score += min(critical * 10 + high * 5, 30)

            if total_vulns > 0:
                findings.append(f"Trivy: {total_vulns} vulnerabilities (CRITICAL={critical}, HIGH={high})")
                if critical > 0 or high > 3:
                    high_priority.append("Trivy: Fix critical/high vulnerabilities before deployment")
            else:
                findings.append("Trivy: No known vulnerabilities found")
        except Exception:
            findings.append("Trivy: it cannot analyze vulnerabilities (parsing error)")
    elif trivy_result.get('status') == 'error':
        findings.append(f"Trivy: Scan error - {trivy_result.get('message')}")

    # -------- YARA: malware signatures --------
    if yara_result.get('status') == 'success':
        if yara_result.get('detected'):
            score += 70
            findings.append("YARA: MALWARE signature(s) detected")
            high_priority.append("YARA: Remove or replace image – malware signature present")
        else:
            findings.append("YARA: No malware signatures found")
    elif yara_result.get('status') == 'error':
        findings.append(f"YARA: Scan error - {yara_result.get('message')}")

    # -------- CLAMAV: antivirus --------
    if clamav_result.get('status') == 'success':
        if clamav_result.get('infected'):
            score += 70
            findings.append("ClamAV: Infected files detected")
            high_priority.append("ClamAV: Infected files – image must NOT be used")
        else:
            findings.append("ClamAV: Image is clean (no infected files)")
    elif clamav_result.get('status') == 'error':
        findings.append(f"ClamAV: Scan error - {clamav_result.get('message')}")

    # -------- FALCO: runtime behavior --------
    if falco_result.get('status') == 'success':
        alerts = falco_result.get('alert_count', 0)
        if alerts > 5:
            extra = min(alerts * 3, 25)
            score += extra
            findings.append(f"Falco: {alerts} suspicious runtime alerts")
            high_priority.append("Falco: Investigate suspicious container behavior before deployment")
        elif alerts > 0:
            findings.append(f"Falco: {alerts} minor runtime alerts")
        else:
            findings.append("Falco: No runtime anomalies detected")
    elif falco_result.get('status') == 'warning':
        findings.append(f"Falco: Warning - {falco_result.get('message')}")
    elif falco_result.get('status') == 'error':
        findings.append(f"Falco: Error - {falco_result.get('message')}")

    # -------- Normalize and assign level --------
    if score < 0:
        score = 0
    if score > 100:
        score = 100

    if score >= 80:
        level = 'CRITICAL'
    elif score >= 50:
        level = 'HIGH'
    elif score >= 20:
        level = 'MEDIUM'
    else:
        level = 'LOW'

    return {
        'risk_score': score,
        'risk_level': level,
        'findings': findings,
        'high_priority': high_priority
    }

