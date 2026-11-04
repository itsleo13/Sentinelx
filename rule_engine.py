from config import RISKY_SERVICES


SEVERITY_SCORE = {
    "Info": 0,
    "Low": 10,
    "Medium": 25,
    "High": 40,
    "Critical": 50
}


def evaluate_port(port, service, banner=None):
    """
    Evaluate an open port using deterministic security rules.

    Returns a list of security findings.
    """

    findings = []

    # -------------------------------------------------
    # Rule 1: Known risky service by port
    # -------------------------------------------------

    if port in RISKY_SERVICES:

        risky_service, severity, recommendation = RISKY_SERVICES[port]

        finding = {
            "type": "risky_service",
            "port": port,
            "service": service,
            "severity": severity,
            "message": (
                f"{risky_service} service is exposed "
                f"on port {port}."
            ),
            "recommendation": recommendation,
            "evidence": (
                banner[:200]
                if banner
                else None
            )
        }

        findings.append(finding)

    # -------------------------------------------------
    # Rule 2: Unknown service
    # -------------------------------------------------

    if service == "Unknown":

        findings.append({
            "type": "unknown_service",
            "port": port,
            "service": service,
            "severity": "Info",
            "message": (
                f"An open port was detected on port {port}, "
                "but the service could not be identified."
            ),
            "recommendation": (
                "Investigate the service running on this port "
                "and verify that the exposure is authorized."
            ),
            "evidence": (
                banner[:200]
                if banner
                else None
            )
        })

    return findings


def calculate_finding_score(findings):
    """
    Calculate a simple deterministic risk score
    from security findings.
    """

    score = 0

    for finding in findings:

        severity = finding.get(
            "severity",
            "Info"
        )

        score += SEVERITY_SCORE.get(
            severity,
            0
        )

    return min(score, 100)


def evaluate_scan(open_ports):
    """
    Evaluate multiple open ports.

    open_ports should contain dictionaries like:

    {
        "port": 445,
        "service": "microsoft-ds",
        "banner": None
    }
    """

    all_findings = []

    for item in open_ports:

        findings = evaluate_port(
            item.get("port"),
            item.get("service", "Unknown"),
            item.get("banner")
        )

        all_findings.extend(findings)

    risk_score = calculate_finding_score(
        all_findings
    )

    return {
        "risk_score": risk_score,
        "findings": all_findings
    }