from config import RISKY_SERVICES


SEVERITY_SCORE = {
    "Critical": 50,
    "High": 30,
    "Medium": 15,
    "Low": 5,
    "Info": 0
}


PRIORITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Info": 4
}


def analyze_port(port_data):

    port = port_data["port"]

    finding = {
        "port": port,
        "service": port_data["service"],
        "severity": "Info",
        "evidence": [],
        "recommendation": "No specific recommendation."
    }

    # ----------------------------------------
    # Known risky services
    # ----------------------------------------

    if port in RISKY_SERVICES:

        name, severity, recommendation = \
            RISKY_SERVICES[port]

        finding["service"] = name
        finding["severity"] = severity
        finding["recommendation"] = recommendation

        finding["evidence"].append(
            f"TCP port {port} is exposed."
        )

    # ----------------------------------------
    # Banner information
    # ----------------------------------------

    if port_data.get("banner"):

        finding["evidence"].append(
            "Service returned an application banner."
        )

    # ----------------------------------------
    # Individual risk score
    # ----------------------------------------

    finding["risk_score"] = SEVERITY_SCORE.get(
        finding["severity"],
        0
    )

    return finding


def prioritize_findings(findings):

    for finding in findings:

        severity = finding.get(
            "severity",
            "Info"
        )

        finding["priority"] = (
            PRIORITY_ORDER.get(
                severity,
                4
            ) + 1
        )

    findings.sort(
        key=lambda x: (
            x["priority"],
            -x.get("risk_score", 0)
        )
    )

    return findings


def analyze_scan(open_ports):

    findings = []

    for port in open_ports:

        findings.append(
            analyze_port(port)
        )

    return prioritize_findings(
        findings
    )


def deduplicate_findings(findings):
    """
    Remove duplicate findings.

    Findings are considered duplicates when they
    refer to the same port, service and severity.
    """

    unique = {}

    order = []

    for finding in findings:

        key = (
            finding.get("port"),
            finding.get("service"),
            finding.get("severity")
        )

        if key not in unique:

            unique[key] = finding
            order.append(key)

        else:

            existing = unique[key]

            # Merge evidence
            for evidence in finding.get(
                "evidence",
                []
            ):

                if evidence not in existing[
                    "evidence"
                ]:

                    existing[
                        "evidence"
                    ].append(
                        evidence
                    )

            # Keep the higher risk score
            existing_score = existing.get(
                "risk_score",
                0
            )

            new_score = finding.get(
                "risk_score",
                0
            )

            if new_score > existing_score:

                existing[
                    "risk_score"
                ] = new_score

    unique_findings = [
        unique[key]
        for key in order
    ]

    return prioritize_findings(
        unique_findings
    )


def get_top_findings(
    findings,
    limit=5
):
    """
    Return the highest-priority findings.
    """

    return findings[:limit]


def calculate_risk(findings):

    score = 0

    for finding in findings:

        score += finding.get(
            "risk_score",
            0
        )

    return min(score, 100)