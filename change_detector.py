# ============================================================
# SENTINELX CHANGE DETECTION ENGINE
# ============================================================

from history import load_history


# ============================================================
# HELPERS
# ============================================================

def _port_number(item):

    if isinstance(item, dict):
        return item.get("port")

    if isinstance(item, int):
        return item

    return None


def _service_key(item):

    if not isinstance(item, dict):
        return None

    return (
        item.get("port"),
        item.get(
            "protocol",
            "TCP"
        ),
        item.get(
            "service",
            "Unknown"
        )
    )


def _finding_key(item):

    if not isinstance(item, dict):
        return None

    evidence = item.get(
        "evidence",
        []
    )

    # Lists cannot be stored directly
    # inside a set. Convert evidence into
    # a stable hashable representation.
    if isinstance(evidence, list):
        evidence = tuple(
            str(value)
            for value in evidence
        )
    elif isinstance(evidence, dict):
        evidence = tuple(
            sorted(
                (
                    str(key),
                    str(value)
                )
                for key, value in evidence.items()
            )
        )
    else:
        evidence = str(
            evidence
        )

    return (
        item.get("port"),
        item.get("service"),
        item.get("severity"),
        evidence
    )

# ============================================================
# PORT CHANGES
# ============================================================

def detect_port_changes(
    previous,
    current
):

    old_ports = {
        _port_number(item)
        for item in previous.get(
            "open_ports",
            []
        )
    }

    new_ports = {
        _port_number(item)
        for item in current.get(
            "open_ports",
            []
        )
    }

    old_ports.discard(None)
    new_ports.discard(None)

    return {

        "new_ports": sorted(
            new_ports - old_ports
        ),

        "closed_ports": sorted(
            old_ports - new_ports
        )
    }


# ============================================================
# SERVICE CHANGES
# ============================================================

def detect_service_changes(
    previous,
    current
):

    old_services = {
        _service_key(item)
        for item in previous.get(
            "open_ports",
            []
        )
        if _service_key(item)
    }

    new_services = {
        _service_key(item)
        for item in current.get(
            "open_ports",
            []
        )
        if _service_key(item)
    }

    added = (
        new_services -
        old_services
    )

    removed = (
        old_services -
        new_services
    )

    return {

        "new_services": [
            {
                "port": item[0],
                "protocol": item[1],
                "service": item[2]
            }
            for item in sorted(
                added,
                key=lambda x: (
                    x[0] or 0,
                    x[1] or "",
                    x[2] or ""
                )
            )
        ],

        "removed_services": [
            {
                "port": item[0],
                "protocol": item[1],
                "service": item[2]
            }
            for item in sorted(
                removed,
                key=lambda x: (
                    x[0] or 0,
                    x[1] or "",
                    x[2] or ""
                )
            )
        ]
    }


# ============================================================
# FINDING CHANGES
# ============================================================

def detect_finding_changes(
    previous,
    current
):

    old_findings = {
        _finding_key(item)
        for item in previous.get(
            "findings",
            []
        )
        if _finding_key(item)
    }

    new_findings = {
        _finding_key(item)
        for item in current.get(
            "findings",
            []
        )
        if _finding_key(item)
    }

    added = (
        new_findings -
        old_findings
    )

    resolved = (
        old_findings -
        new_findings
    )

    return {

        "new_findings": [
            {
                "port": item[0],
                "service": item[1],
                "severity": item[2],
                "evidence": item[3]
            }
            for item in added
        ],

        "resolved_findings": [
            {
                "port": item[0],
                "service": item[1],
                "severity": item[2],
                "evidence": item[3]
            }
            for item in resolved
        ]
    }


# ============================================================
# RISK CHANGE
# ============================================================

def detect_risk_change(
    previous,
    current
):

    old_score = previous.get(
        "risk_score",
        0
    )

    new_score = current.get(
        "risk_score",
        0
    )

    try:
        old_score = float(
            old_score
        )
    except (
        TypeError,
        ValueError
    ):
        old_score = 0

    try:
        new_score = float(
            new_score
        )
    except (
        TypeError,
        ValueError
    ):
        new_score = 0

    difference = (
        new_score -
        old_score
    )

    if difference > 0:
        direction = "Increased"

    elif difference < 0:
        direction = "Decreased"

    else:
        direction = "Unchanged"

    return {

        "previous_score":
            old_score,

        "current_score":
            new_score,

        "difference":
            difference,

        "direction":
            direction
    }


# ============================================================
# ML CHANGE
# ============================================================

def detect_ml_change(
    previous,
    current
):

    old_ml = previous.get(
        "ml_analysis",
        {}
    )

    new_ml = current.get(
        "ml_analysis",
        {}
    )

    old_status = old_ml.get(
        "status",
        "Unavailable"
    )

    new_status = new_ml.get(
        "status",
        "Unavailable"
    )

    old_prediction = old_ml.get(
        "prediction"
    )

    new_prediction = new_ml.get(
        "prediction"
    )

    return {

        "previous_status":
            old_status,

        "current_status":
            new_status,

        "status_changed":
            old_status != new_status,

        "previous_prediction":
            old_prediction,

        "current_prediction":
            new_prediction,

        "prediction_changed":
            old_prediction != new_prediction
    }


# ============================================================
# HYBRID CHANGE
# ============================================================

def detect_hybrid_change(
    previous,
    current
):

    old_hybrid = previous.get(
        "hybrid_analysis",
        {}
    )

    new_hybrid = current.get(
        "hybrid_analysis",
        {}
    )

    old_score = old_hybrid.get(
        "hybrid_score",
        0
    )

    new_score = new_hybrid.get(
        "hybrid_score",
        0
    )

    try:
        old_score = float(
            old_score
        )
    except (
        TypeError,
        ValueError
    ):
        old_score = 0

    try:
        new_score = float(
            new_score
        )
    except (
        TypeError,
        ValueError
    ):
        new_score = 0

    return {

        "previous_score":
            old_score,

        "current_score":
            new_score,

        "difference":
            new_score - old_score,

        "previous_risk":
            old_hybrid.get(
                "risk_level",
                "Info"
            ),

        "current_risk":
            new_hybrid.get(
                "risk_level",
                "Info"
            )
    }


# ============================================================
# COMPLETE CHANGE ANALYSIS
# ============================================================

def analyze_changes(
    previous,
    current
):

    if not previous:

        return {

            "baseline_available":
                False,

            "message":
                "No previous scan available.",

            "new_ports":
                [],

            "closed_ports":
                [],

            "new_services":
                [],

            "removed_services":
                [],

            "new_findings":
                [],

            "resolved_findings":
                [],

            "risk_change": {
                "previous_score": 0,
                "current_score":
                    current.get(
                        "risk_score",
                        0
                    ),
                "difference":
                    current.get(
                        "risk_score",
                        0
                    ),
                "direction":
                    "Baseline"
            },

            "ml_change": {},

            "hybrid_change": {}
        }

    port_changes = (
        detect_port_changes(
            previous,
            current
        )
    )

    service_changes = (
        detect_service_changes(
            previous,
            current
        )
    )

    finding_changes = (
        detect_finding_changes(
            previous,
            current
        )
    )

    risk_change = (
        detect_risk_change(
            previous,
            current
        )
    )

    ml_change = (
        detect_ml_change(
            previous,
            current
        )
    )

    hybrid_change = (
        detect_hybrid_change(
            previous,
            current
        )
    )

    total_changes = (
        len(
            port_changes[
                "new_ports"
            ]
        )
        +
        len(
            port_changes[
                "closed_ports"
            ]
        )
        +
        len(
            service_changes[
                "new_services"
            ]
        )
        +
        len(
            service_changes[
                "removed_services"
            ]
        )
        +
        len(
            finding_changes[
                "new_findings"
            ]
        )
        +
        len(
            finding_changes[
                "resolved_findings"
            ]
        )
    )

    return {

        "baseline_available":
            True,

        "previous_scan":
            previous.get(
                "scan_time"
            ),

        "current_scan":
            current.get(
                "scan_time"
            ),

        "new_ports":
            port_changes[
                "new_ports"
            ],

        "closed_ports":
            port_changes[
                "closed_ports"
            ],

        "new_services":
            service_changes[
                "new_services"
            ],

        "removed_services":
            service_changes[
                "removed_services"
            ],

        "new_findings":
            finding_changes[
                "new_findings"
            ],

        "resolved_findings":
            finding_changes[
                "resolved_findings"
            ],

        "risk_change":
            risk_change,

        "ml_change":
            ml_change,

        "hybrid_change":
            hybrid_change,

        "total_changes":
            total_changes
    }


# ============================================================
# COMPARE CURRENT AGAINST LAST HISTORY
# ============================================================

def compare_current_with_baseline(
    current
):

    history = load_history()

    if not history:

        return analyze_changes(
            None,
            current
        )

    previous = history[-1]

    return analyze_changes(
        previous,
        current
    )


# ============================================================
# PRINT CHANGE REPORT
# ============================================================

def print_change_report(
    result
):

    width = 66

    def border():
        print("╔" + "═" * width + "╗")

    def divider():
        print("╠" + "═" * width + "╣")

    def bottom():
        print("╚" + "═" * width + "╝")

    def row(text=""):
        print("║ " + str(text)[:width - 2].ljust(width - 2) + " ║")

    def section(title):
        print()
        print("╭" + "─" * 18 + f" {title} " + "─" * 18 + "╮")

    def section_end():
        print("╰" + "─" * 58 + "╯")

    print()

    # ========================================================
    # HEADER
    # ========================================================

    border()
    row("SENTINELX CHANGE INTELLIGENCE")
    row("Security Baseline Comparison Engine")
    divider()

    if not result.get(
        "baseline_available",
        False
    ):

        row("BASELINE STATUS   ⚠ NOT AVAILABLE")
        row()

        message = result.get(
            "message",
            "No previous scan is available for comparison."
        )

        row(message)

        bottom()

        return

    total_changes = result.get(
        "total_changes",
        0
    )

    row("BASELINE STATUS   ✓ AVAILABLE")
    row(f"TOTAL CHANGES     {total_changes}")
    bottom()

    # ========================================================
    # PORT CHANGES
    # ========================================================

    new_ports = result.get(
        "new_ports",
        []
    )

    closed_ports = result.get(
        "closed_ports",
        []
    )

    print()
    border()
    row("PORT CHANGE DETECTION")
    divider()
    row(
        f"NEW PORTS       : "
        f"{new_ports if new_ports else 'None'}"
    )
    row(
        f"CLOSED PORTS    : "
        f"{closed_ports if closed_ports else 'None'}"
    )
    bottom()

    # ========================================================
    # SERVICE CHANGES
    # ========================================================

    new_services = result.get(
        "new_services",
        []
    )

    removed_services = result.get(
        "removed_services",
        []
    )

    print()
    border()
    row("SERVICE CHANGE DETECTION")
    divider()

    if new_services:

        row("NEW SERVICES")

        for service in new_services:

            row(
                f"+ "
                f"{service.get('port')}/"
                f"{service.get('protocol')} "
                f"{service.get('service')}"
            )

    else:

        row("NEW SERVICES     : None")

    row()

    if removed_services:

        row("REMOVED SERVICES")

        for service in removed_services:

            row(
                f"- "
                f"{service.get('port')}/"
                f"{service.get('protocol')} "
                f"{service.get('service')}"
            )

    else:

        row("REMOVED SERVICES : None")

    bottom()

    # ========================================================
    # FINDING CHANGES
    # ========================================================

    new_findings = result.get(
        "new_findings",
        []
    )

    resolved_findings = result.get(
        "resolved_findings",
        []
    )

    print()
    border()
    row("SECURITY FINDING CHANGES")
    divider()
    row(
        f"NEW FINDINGS       : "
        f"{len(new_findings)}"
    )
    row(
        f"RESOLVED FINDINGS  : "
        f"{len(resolved_findings)}"
    )
    bottom()

    # ========================================================
    # RISK CHANGE
    # ========================================================

    risk = result.get(
        "risk_change",
        {}
    )

    print()
    border()
    row("RISK SCORE CHANGE")
    divider()
    row(
        f"PREVIOUS SCORE   : "
        f"{risk.get('previous_score', 0)}/100"
    )
    row(
        f"CURRENT SCORE    : "
        f"{risk.get('current_score', 0)}/100"
    )
    row(
        f"CHANGE           : "
        f"{risk.get('difference', 0)}"
    )
    row(
        f"DIRECTION        : "
        f"{risk.get('direction', 'Unknown')}"
    )
    bottom()

    # ========================================================
    # ML CHANGE
    # ========================================================

    ml = result.get(
        "ml_change",
        {}
    )

    print()
    border()
    row("ML BEHAVIOR CHANGE")
    divider()
    row(
        f"PREVIOUS STATUS  : "
        f"{ml.get('previous_status', 'Unknown')}"
    )
    row(
        f"CURRENT STATUS   : "
        f"{ml.get('current_status', 'Unknown')}"
    )
    row(
        f"STATUS CHANGED   : "
        f"{ml.get('status_changed', False)}"
    )
    bottom()

    # ========================================================
    # HYBRID CHANGE
    # ========================================================

    hybrid = result.get(
        "hybrid_change",
        {}
    )

    print()
    border()
    row("HYBRID RISK INTELLIGENCE")
    divider()
    row(
        f"PREVIOUS SCORE   : "
        f"{hybrid.get('previous_score', 0)}/100"
    )
    row(
        f"CURRENT SCORE    : "
        f"{hybrid.get('current_score', 0)}/100"
    )
    row(
        f"CHANGE           : "
        f"{hybrid.get('difference', 0)}"
    )
    row(
        f"PREVIOUS RISK    : "
        f"{hybrid.get('previous_risk', 'Info')}"
    )
    row(
        f"CURRENT RISK     : "
        f"{hybrid.get('current_risk', 'Info')}"
    )
    bottom()

