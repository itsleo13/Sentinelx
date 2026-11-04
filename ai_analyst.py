"""
SentinelX AI Security Analyst v2

Provides:
- Security summary
- Finding analysis
- Impact assessment
- Remediation guidance
- Priority classification

No external API is used.
"""


SEVERITY_PRIORITY = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Info": 0
}


def get_highest_severity(findings):

    if not findings:
        return "Info"

    return max(
        findings,
        key=lambda finding:
            SEVERITY_PRIORITY.get(
                finding.get(
                    "severity",
                    "Info"
                ),
                0
            )
    ).get(
        "severity",
        "Info"
    )


def get_priority(severity):

    if severity == "Critical":
        return "Immediate"

    if severity == "High":
        return "High"

    if severity == "Medium":
        return "Medium"

    if severity == "Low":
        return "Low"

    return "Informational"


def get_impact(
    severity,
    service,
    port
):

    if severity == "Critical":

        return (
            "This exposure may represent a "
            "serious security weakness and "
            "requires immediate investigation."
        )

    if severity == "High":

        return (
            f"The exposed {service} service on "
            f"TCP port {port} represents "
            "significant security exposure."
        )

    if severity == "Medium":

        return (
            f"The {service} service on TCP port "
            f"{port} may increase the attack "
            "surface and should be reviewed."
        )

    if severity == "Low":

        return (
            f"The service on TCP port {port} "
            "represents limited exposure but "
            "should be verified."
        )

    return (
        f"The service on TCP port {port} was "
        "identified as informational evidence. "
        "No vulnerability is established by "
        "this finding alone."
    )


def get_action(
    finding
):

    recommendation = finding.get(
        "recommendation"
    )

    service = finding.get(
        "service",
        "Unknown"
    )

    port = finding.get(
        "port",
        "Unknown"
    )

    severity = finding.get(
        "severity",
        "Info"
    )

    if recommendation and recommendation != (
        "No specific recommendation."
    ):

        return recommendation

    if severity == "Info":

        return (
            f"Verify that {service} on TCP "
            f"port {port} is intentionally "
            "exposed and restrict access if "
            "the service is not required."
        )

    return (
        f"Investigate the service running on "
        f"TCP port {port} and verify that its "
        "exposure is authorized."
    )


def analyze_finding(
    finding
):

    severity = finding.get(
        "severity",
        "Info"
    )

    port = finding.get(
        "port",
        "Unknown"
    )

    service = finding.get(
        "service",
        "Unknown"
    )

    return {

        "port":
            port,

        "service":
            service,

        "severity":
            severity,

        "priority":
            get_priority(
                severity
            ),

        "impact":
            get_impact(
                severity,
                service,
                port
            ),

        "action":
            get_action(
                finding
            ),

        "evidence":
            finding.get(
                "evidence",
                []
            )
    }


def build_summary(
    findings,
    hybrid_analysis
):

    risk_level = hybrid_analysis.get(
        "risk_level",
        "Info"
    )

    hybrid_score = hybrid_analysis.get(
        "hybrid_score",
        0
    )

    if not findings:

        return (
            "No security findings were "
            "identified. The scan did not "
            "produce rule-based security "
            "alerts."
        )

    highest = get_highest_severity(
        findings
    )

    count = len(findings)

    return (
        f"SentinelX identified {count} "
        f"security finding(s). The highest "
        f"observed severity is {highest}. "
        f"The combined hybrid assessment "
        f"is {risk_level} "
        f"({hybrid_score}/100)."
    )


def build_evidence(
    findings
):

    evidence = []

    for finding in findings:

        for item in finding.get(
            "evidence",
            []
        ):

            if (
                item
                and item not in evidence
            ):

                evidence.append(
                    item
                )

    return evidence


def generate_recommendations(
    findings
):

    recommendations = []

    ordered = sorted(
        findings,
        key=lambda finding:
            SEVERITY_PRIORITY.get(
                finding.get(
                    "severity",
                    "Info"
                ),
                0
            ),
        reverse=True
    )

    for finding in ordered:

        action = get_action(
            finding
        )

        if action not in recommendations:

            recommendations.append(
                action
            )

    if not recommendations:

        recommendations.append(
            "Continue monitoring the target "
            "for unexpected changes."
        )

    return recommendations


def generate_security_assessment(
    findings,
    hybrid_analysis
):

    analyzed_findings = [
        analyze_finding(
            finding
        )
        for finding in findings
    ]

    analyzed_findings.sort(
        key=lambda finding:
            SEVERITY_PRIORITY.get(
                finding["severity"],
                0
            ),
        reverse=True
    )

    top_issue = (
        analyzed_findings[0]
        if analyzed_findings
        else {
            "port": None,
            "service": None,
            "severity": "Info",
            "priority": "Informational",
            "impact": (
                "No security finding "
                "requires immediate attention."
            ),
            "action": (
                "Continue monitoring "
                "the target."
            ),
            "evidence": []
        }
    )

    return {

        "summary":
            build_summary(
                findings,
                hybrid_analysis
            ),

        "risk_level":
            hybrid_analysis.get(
                "risk_level",
                "Info"
            ),

        "hybrid_score":
            hybrid_analysis.get(
                "hybrid_score",
                0
            ),

        "top_issue":
            top_issue,

        "findings":
            analyzed_findings,

        "evidence":
            build_evidence(
                findings
            ),

        "recommendations":
            generate_recommendations(
                findings
            ),

        "analyst_note": (
            "Assessment generated from "
            "SentinelX rule-based findings "
            "and hybrid behavioral analysis."
        )
    }