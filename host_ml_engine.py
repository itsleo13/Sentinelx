# ============================================================
# SENTINELX HOST ML + HYBRID ENGINE
# ============================================================

from ml_analyzer import MLAnalyzer
from hybrid_engine import generate_hybrid_analysis


# ============================================================
# RISKY PORTS
# ============================================================

try:

    from ml_analyzer import RISKY_PORTS

except ImportError:

    RISKY_PORTS = set()


# ============================================================
# HOST -> ML FEATURE VECTOR
# ============================================================

def extract_host_features(host):

    open_ports = host.get(
        "open_ports",
        []
    )

    services = host.get(
        "services",
        []
    )

    findings = host.get(
        "findings",
        []
    )

    total_open_ports = len(
        open_ports
    )

    risky_ports = 0

    unknown_services = 0

    high_risk_findings = 0

    medium_risk_findings = 0

    # --------------------------------------------------------
    # Ports
    # --------------------------------------------------------

    for port_data in open_ports:

        if not isinstance(
            port_data,
            dict
        ):
            continue

        port = port_data.get(
            "port"
        )

        if port in RISKY_PORTS:

            risky_ports += 1

        service = port_data.get(
            "service"
        )

        if (
            service is None
            or service == "Unknown"
            or str(service).lower()
            == "unknown"
        ):

            unknown_services += 1

    # --------------------------------------------------------
    # Services
    #
    # If the service information is more reliable than the
    # open-port record, use it as an additional fallback.
    # --------------------------------------------------------

    if not open_ports:

        for service_data in services:

            if not isinstance(
                service_data,
                dict
            ):
                continue

            port = service_data.get(
                "port"
            )

            if port in RISKY_PORTS:

                risky_ports += 1

            service = service_data.get(
                "service"
            )

            if (
                service is None
                or str(service).lower()
                == "unknown"
            ):

                unknown_services += 1

    # --------------------------------------------------------
    # Findings
    # --------------------------------------------------------

    for finding in findings:

        if not isinstance(
            finding,
            dict
        ):
            continue

        severity = finding.get(
            "severity",
            "Info"
        )

        if severity in (
            "Critical",
            "High"
        ):

            high_risk_findings += 1

        elif severity == "Medium":

            medium_risk_findings += 1

    # --------------------------------------------------------
    # Rule-based risk
    # --------------------------------------------------------

    risk_score = host.get(
        "risk_score",
        0
    )

    try:

        risk_score = float(
            risk_score
        )

    except (
        TypeError,
        ValueError
    ):

        risk_score = 0

    return [

        total_open_ports,

        risky_ports,

        unknown_services,

        high_risk_findings,

        medium_risk_findings,

        risk_score
    ]


# ============================================================
# ANALYZE SINGLE HOST
# ============================================================

def analyze_host_ml(
    host,
    analyzer=None
):

    if analyzer is None:

        analyzer = MLAnalyzer()

        training = (
            analyzer.train_from_history()
        )

    else:

        training = {
            "trained":
                analyzer.trained,
            "samples":
                None,
            "message":
                "Existing ML analyzer supplied."
        }

    features = (
        extract_host_features(
            host
        )
    )

    # --------------------------------------------------------
    # Not enough history
    # --------------------------------------------------------

    if not analyzer.trained:

        return {

            "status":
                "Unavailable",

            "prediction":
                None,

            "anomaly_score":
                None,

            "message":
                (
                    "ML model is not trained. "
                    "At least 5 historical scans "
                    "are required."
                ),

            "features": {

                "total_open_ports":
                    features[0],

                "risky_ports":
                    features[1],

                "unknown_services":
                    features[2],

                "high_risk_findings":
                    features[3],

                "medium_risk_findings":
                    features[4],

                "risk_score":
                    features[5]
            },

            "training":
                training
        }

    # --------------------------------------------------------
    # Prediction
    # --------------------------------------------------------

    prediction = analyzer.model.predict(
        [features]
    )[0]

    anomaly_score = (
        analyzer.model.decision_function(
            [features]
        )[0]
    )

    if prediction == -1:

        status = "Anomalous"

    else:

        status = "Normal"

    return {

        "status":
            status,

        "prediction":
            int(prediction),

        "anomaly_score":
            round(
                float(
                    anomaly_score
                ),
                4
            ),

        "message":
            (
                "Host behavior compared "
                "against SentinelX historical "
                "baseline."
            ),

        "features": {

            "total_open_ports":
                features[0],

            "risky_ports":
                features[1],

            "unknown_services":
                features[2],

            "high_risk_findings":
                features[3],

            "medium_risk_findings":
                features[4],

            "risk_score":
                features[5]
        },

        "training":
            training
    }


# ============================================================
# HOST HYBRID ANALYSIS
# ============================================================

def analyze_host_hybrid(
    host,
    ml_result
):

    rule_score = host.get(
        "risk_score",
        0
    )

    try:

        rule_score = float(
            rule_score
        )

    except (
        TypeError,
        ValueError
    ):

        rule_score = 0

    hybrid_result = (
        generate_hybrid_analysis(
            rule_score,
            ml_result
        )
    )

    return hybrid_result


# ============================================================
# COMPLETE HOST INTELLIGENCE
# ============================================================

def enrich_host_with_ml(
    host,
    analyzer=None
):

    ml_result = (
        analyze_host_ml(
            host,
            analyzer
        )
    )

    hybrid_result = (
        analyze_host_hybrid(
            host,
            ml_result
        )
    )

    enriched = dict(
        host
    )

    enriched[
        "ml_analysis"
    ] = ml_result

    enriched[
        "hybrid_analysis"
    ] = hybrid_result

    enriched[
        "ml_status"
    ] = ml_result.get(
        "status"
    )

    enriched[
        "ml_prediction"
    ] = ml_result.get(
        "prediction"
    )

    enriched[
        "ml_anomaly_score"
    ] = ml_result.get(
        "anomaly_score"
    )

    enriched[
        "hybrid_score"
    ] = hybrid_result.get(
        "hybrid_score",
        0
    )

    enriched[
        "hybrid_risk_level"
    ] = hybrid_result.get(
        "risk_level",
        "Info"
    )

    return enriched


# ============================================================
# ENRICH NETWORK
# ============================================================

def enrich_network_with_ml(
    correlated_network
):

    analyzer = MLAnalyzer()

    training = (
        analyzer.train_from_history()
    )

    enriched_hosts = []

    for host in correlated_network.get(
        "hosts",
        []
    ):

        ml_result = (
            analyze_host_ml(
                host,
                analyzer
            )
        )

        hybrid_result = (
            analyze_host_hybrid(
                host,
                ml_result
            )
        )

        enriched = dict(
            host
        )

        enriched[
            "ml_analysis"
        ] = ml_result

        enriched[
            "hybrid_analysis"
        ] = hybrid_result

        enriched[
            "ml_status"
        ] = ml_result.get(
            "status"
        )

        enriched[
            "ml_prediction"
        ] = ml_result.get(
            "prediction"
        )

        enriched[
            "ml_anomaly_score"
        ] = ml_result.get(
            "anomaly_score"
        )

        enriched[
            "hybrid_score"
        ] = hybrid_result.get(
            "hybrid_score",
            0
        )

        enriched[
            "hybrid_risk_level"
        ] = hybrid_result.get(
            "risk_level",
            "Info"
        )

        enriched_hosts.append(
            enriched
        )

    # --------------------------------------------------------
    # Network hybrid score
    # --------------------------------------------------------

    network_hybrid_score = 0

    for host in enriched_hosts:

        score = host.get(
            "hybrid_score",
            0
        )

        try:

            score = float(
                score
            )

        except (
            TypeError,
            ValueError
        ):

            score = 0

        network_hybrid_score = max(
            network_hybrid_score,
            score
        )

    # --------------------------------------------------------
    # Network ML anomaly count
    # --------------------------------------------------------

    anomalous_hosts = sum(
        1
        for host in enriched_hosts
        if host.get(
            "ml_status"
        ) == "Anomalous"
    )

    normal_hosts = sum(
        1
        for host in enriched_hosts
        if host.get(
            "ml_status"
        ) == "Normal"
    )

    unavailable_hosts = sum(
        1
        for host in enriched_hosts
        if host.get(
            "ml_status"
        ) == "Unavailable"
    )

    result = dict(
        correlated_network
    )

    result[
        "hosts"
    ] = enriched_hosts

    result[
        "ml_training"
    ] = training

    result[
        "network_hybrid_score"
    ] = network_hybrid_score

    result[
        "ml_anomalous_hosts"
    ] = anomalous_hosts

    result[
        "ml_normal_hosts"
    ] = normal_hosts

    result[
        "ml_unavailable_hosts"
    ] = unavailable_hosts

    return result


# ============================================================
# PRINT ML + HYBRID REPORT
# ============================================================

def print_host_ml_report(
    result
):

    print()

    print("=" * 72)
    print("HOST ML + HYBRID INTELLIGENCE")
    print("=" * 72)

    training = result.get(
        "ml_training",
        {}
    )

    print(
        f"ML Trained        : "
        f"{training.get('trained', False)}"
    )

    print(
        f"Training Samples  : "
        f"{training.get('samples', 'Unknown')}"
    )

    print(
        f"Network Hybrid    : "
        f"{result.get('network_hybrid_score', 0)}/100"
    )

    print(
        f"ML Anomalous      : "
        f"{result.get('ml_anomalous_hosts', 0)}"
    )

    print(
        f"ML Normal         : "
        f"{result.get('ml_normal_hosts', 0)}"
    )

    print(
        f"ML Unavailable    : "
        f"{result.get('ml_unavailable_hosts', 0)}"
    )

    print()
    print("-" * 72)
    print("PER-HOST ML ANALYSIS")
    print("-" * 72)

    for host in result.get(
        "hosts",
        []
    ):

        print()

        print(
            f"Host: "
            f"{host.get('ip', 'Unknown')}"
        )

        print(
            f"  Rule Risk       : "
            f"{host.get('risk_score', 0)}/100"
        )

        print(
            f"  ML Status       : "
            f"{host.get('ml_status', 'Unavailable')}"
        )

        print(
            f"  ML Prediction   : "
            f"{host.get('ml_prediction')}"
        )

        anomaly = host.get(
            "ml_anomaly_score"
        )

        if anomaly is None:

            print(
                "  ML Anomaly      : N/A"
            )

        else:

            print(
                f"  ML Anomaly      : "
                f"{anomaly}"
            )

        print(
            f"  Hybrid Score    : "
            f"{host.get('hybrid_score', 0)}/100"
        )

        print(
            f"  Hybrid Risk     : "
            f"{host.get('hybrid_risk_level', 'Info')}"
        )