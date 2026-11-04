# ============================================================
# SECURITY FINDINGS DISPLAY
# ============================================================

def print_findings(
    findings,
    risk_score
):

    print()

    risk_color = get_risk_color(
        "Critical"
        if risk_score >= 90
        else "High"
        if risk_score >= 70
        else "Medium"
        if risk_score >= 40
        else "Low"
        if risk_score > 0
        else "Info"
    )

    ui_border("Security Analysis")

    ui_line(
        " RULE-BASED SECURITY INTELLIGENCE",
        Fore.WHITE + Style.BRIGHT
    )

    ui_line()

    ui_line(
        f" RISK SCORE    : {risk_score}/100",
        risk_color + Style.BRIGHT
    )

    ui_line(
        f" TOTAL FINDINGS: {len(findings)}",
        Fore.YELLOW
    )

    ui_end()

    if not findings:

        print()

        ui_border("Finding Status")

        ui_line(
            " No rule-based security findings detected.",
            Fore.GREEN
        )

        ui_line(
            " Continue monitoring for unexpected changes.",
            Fore.WHITE
        )

        ui_end()

        return

    for index, finding in enumerate(
        findings,
        start=1
    ):

        severity = finding.get(
            "severity",
            "Info"
        )

        severity_color = get_risk_color(
            severity
        )

        port = finding.get(
            "port",
            "Unknown"
        )

        service = finding.get(
            "service",
            "Unknown"
        )

        recommendation = finding.get(
            "recommendation",
            "Review exposure."
        )

        print()

        ui_border(
            f" Finding {index} "
        )

        ui_line(
            f" SEVERITY      : {severity}",
            severity_color + Style.BRIGHT
        )

        ui_line(
            f" TARGET PORT   : {port}/TCP",
            Fore.WHITE
        )

        ui_line(
            f" SERVICE       : {service}",
            Fore.CYAN
        )

        ui_line()

        ui_line(
            " EVIDENCE:",
            Fore.YELLOW + Style.BRIGHT
        )

        evidence_list = finding.get(
            "evidence",
            []
        )

        if evidence_list:

            for evidence in evidence_list:

                text = (
                    "   • "
                    + str(evidence)
                )

                ui_line(
                    text,
                    Fore.WHITE
                )

        else:

            ui_line(
                "   • No additional evidence available.",
                Fore.WHITE
            )

        ui_line()

        ui_line(
            " RECOMMENDATION:",
            Fore.YELLOW + Style.BRIGHT
        )

        ui_line(
            "   " + str(recommendation),
            Fore.GREEN
        )

        ui_end()


# ============================================================
# TOP FINDINGS DISPLAY
# ============================================================

def print_top_findings(
    findings
):

    print()

    ui_border("Top Security Findings")

    if not findings:

        ui_line(
            " No security findings available.",
            Fore.GREEN
        )

        ui_end()

        return

    top = get_top_findings(
        findings
    )

    for index, finding in enumerate(
        top,
        start=1
    ):

        severity = finding.get(
            "severity",
            "Info"
        )

        severity_color = get_risk_color(
            severity
        )

        port = finding.get(
            "port",
            "Unknown"
        )

        service = finding.get(
            "service",
            "Unknown"
        )

        ui_line(
            f" [{index}] {severity.upper()}",
            severity_color + Style.BRIGHT
        )

        ui_line(
            f"     {port}/TCP  •  {service}",
            Fore.WHITE
        )

        if index < len(top):

            ui_line(
                " ────────────────────────────────────────────────",
                Fore.CYAN
            )

    ui_end()


# ============================================================
# ML DISPLAY
# ============================================================

def print_ml_analysis(
    ml_result
):

    print()

    status = ml_result.get(
        "status",
        "Unknown"
    )

    if status == "Anomalous":

        status_color = (
            Fore.RED
            + Style.BRIGHT
        )

    elif status == "Normal":

        status_color = (
            Fore.GREEN
            + Style.BRIGHT
        )

    else:

        status_color = Fore.YELLOW

    training = ml_result.get(
        "training",
        {}
    )

    prediction = ml_result.get(
        "prediction",
        "Unknown"
    )

    anomaly_score = ml_result.get(
        "anomaly_score",
        0
    )

    samples = training.get(
        "samples",
        0
    )

    message = ml_result.get(
        "message",
        ""
    )

    ui_border("ML Anomaly Intelligence")

    ui_line(
        " HISTORICAL BEHAVIOR ANALYSIS",
        Fore.WHITE + Style.BRIGHT
    )

    ui_line()

    ui_line(
        f" STATUS        : {status}",
        status_color
    )

    ui_line(
        f" PREDICTION    : {prediction}",
        Fore.WHITE
    )

    ui_line(
        f" ANOMALY SCORE : {anomaly_score}",
        Fore.YELLOW
    )

    ui_line(
        f" TRAINING DATA : {samples} historical scans",
        Fore.CYAN
    )

    ui_line()

    ui_line(
        " ANALYST NOTE:",
        Fore.YELLOW + Style.BRIGHT
    )

    ui_line(
        "   " + str(message),
        Fore.WHITE
    )

    ui_end()


# ============================================================
# HYBRID DISPLAY
# ============================================================

def print_hybrid_analysis(
    hybrid
):

    print()

    risk_level = hybrid.get(
        "risk_level",
        "Info"
    )

    risk_color = get_risk_color(
        risk_level
    )

    rule_score = hybrid.get(
        "rule_score",
        0
    )

    ml_score = hybrid.get(
        "ml_anomaly_score",
        0
    )

    hybrid_score = hybrid.get(
        "hybrid_score",
        0
    )

    ml_status = hybrid.get(
        "ml_status",
        "Unknown"
    )

    ui_border("Hybrid Security Intelligence")

    ui_line(
        " RULE ENGINE + BEHAVIORAL ANOMALY MODEL",
        Fore.WHITE + Style.BRIGHT
    )

    ui_line()

    ui_line(
        f" RULE RISK     : {rule_score}/100",
        Fore.YELLOW
    )

    ui_line(
        f" ML ANOMALY    : {ml_score}/100",
        Fore.CYAN
    )

    ui_line()

    ui_line(
        f" HYBRID SCORE  : {hybrid_score}/100",
        risk_color + Style.BRIGHT
    )

    ui_line(
        f" RISK LEVEL    : {risk_level}",
        risk_color + Style.BRIGHT
    )

    ui_line(
        f" ML STATUS     : {ml_status}",
        Fore.WHITE
    )

    ui_end()


# ============================================================
# AI SECURITY ANALYST DISPLAY
# ============================================================

def print_ai_assessment(
    assessment
):

    print()

    risk_level = assessment.get(
        "risk_level",
        "Info"
    )

    risk_color = get_risk_color(
        risk_level
    )

    hybrid_score = assessment.get(
        "hybrid_score",
        0
    )

    summary = assessment.get(
        "summary",
        "No summary available."
    )

    ui_border("AI Security Analyst")

    ui_line(
        " AUTOMATED SECURITY ASSESSMENT",
        Fore.WHITE + Style.BRIGHT
    )

    ui_line()

    ui_line(
        f" RISK LEVEL    : {risk_level}",
        risk_color + Style.BRIGHT
    )

    ui_line(
        f" HYBRID SCORE  : {hybrid_score}/100",
        risk_color
    )

    ui_line()

    ui_line(
        " EXECUTIVE SUMMARY:",
        Fore.YELLOW + Style.BRIGHT
    )

    ui_line(
        "   " + str(summary),
        Fore.WHITE
    )

    ui_end()

    top_issue = assessment.get(
        "top_issue"
    )

    if top_issue:

        print()

        severity = top_issue.get(
            "severity",
            "Info"
        )

        severity_color = get_risk_color(
            severity
        )

        ui_border("Priority Security Issue")

        ui_line(
            f" PORT          : {top_issue.get('port', 'Unknown')}",
            Fore.WHITE
        )

        ui_line(
            f" SERVICE       : {top_issue.get('service', 'Unknown')}",
            Fore.CYAN
        )

        ui_line(
            f" SEVERITY      : {severity}",
            severity_color + Style.BRIGHT
        )

        ui_line(
            f" PRIORITY      : {top_issue.get('priority', 'Informational')}",
            Fore.YELLOW
        )

        ui_line()

        ui_line(
            " IMPACT:",
            Fore.YELLOW + Style.BRIGHT
        )

        ui_line(
            "   "
            + str(
                top_issue.get(
                    "impact",
                    "No impact information."
                )
            ),
            Fore.WHITE
        )

        ui_line()

        ui_line(
            " RECOMMENDED ACTION:",
            Fore.YELLOW + Style.BRIGHT
        )

        ui_line(
            "   "
            + str(
                top_issue.get(
                    "action",
                    "Review the finding."
                )
            ),
            Fore.GREEN
        )

        evidence = top_issue.get(
            "evidence",
            []
        )

        if evidence:

            ui_line()

            ui_line(
                " SUPPORTING EVIDENCE:",
                Fore.YELLOW + Style.BRIGHT
            )

            for item in evidence:

                ui_line(
                    "   • " + str(item),
                    Fore.WHITE
                )

        ui_end()

    recommendations = assessment.get(
        "recommendations",
        []
    )

    if recommendations:

        print()

        ui_border("Prioritized Recommendations")

        for index, recommendation in enumerate(
            recommendations,
            start=1
        ):

            ui_line(
                f" [{index}] {recommendation}",
                Fore.GREEN
            )

        ui_end()
