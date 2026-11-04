"""
SentinelX Hybrid Risk Engine

Rule Engine = primary security signal
ML          = supporting behavioral signal
"""


def clamp_score(score):
    return max(
        0,
        min(
            100,
            round(score)
        )
    )


def normalize_ml_anomaly(anomaly_score):

    if anomaly_score is None:
        return 0

    normalized = (
        0.5 - float(anomaly_score)
    ) * 100

    return clamp_score(
        normalized
    )


def calculate_hybrid_score(
    rule_score,
    ml_result,
    rule_weight=0.75,
    ml_weight=0.25
):

    rule_score = clamp_score(
        rule_score
    )

    anomaly_score = ml_result.get(
        "anomaly_score"
    )

    ml_anomaly = normalize_ml_anomaly(
        anomaly_score
    )

    if anomaly_score is None:

        hybrid_score = rule_score

    else:

        hybrid_score = (
            rule_score * rule_weight
            + ml_anomaly * ml_weight
        )

    return {
        "rule_score": rule_score,
        "ml_anomaly_score": ml_anomaly,
        "hybrid_score": clamp_score(
            hybrid_score
        ),
        "weights": {
            "rule_engine": rule_weight,
            "ml": ml_weight
        }
    }


def get_risk_level(
    hybrid_score,
    rule_score,
    ml_anomaly
):
    """
    Rule-based findings have priority.

    ML alone should only raise the risk level
    when the anomaly is significant.
    """

    hybrid_score = clamp_score(
        hybrid_score
    )

    rule_score = clamp_score(
        rule_score
    )

    ml_anomaly = clamp_score(
        ml_anomaly
    )

    # Rule engine remains authoritative
    if rule_score >= 80:
        return "Critical"

    if rule_score >= 60:
        return "High"

    if rule_score >= 30:
        return "Medium"

    # No rule-based security finding.
    # Small ML deviations remain informational.
    if rule_score == 0:

        if ml_anomaly >= 70:
            return "Low"

        return "Info"

    # Small rule score + strong anomaly
    if hybrid_score >= 60:
        return "High"

    if hybrid_score >= 30:
        return "Medium"

    if hybrid_score > 0:
        return "Low"

    return "Info"


def generate_hybrid_analysis(
    rule_score,
    ml_result
):

    result = calculate_hybrid_score(
        rule_score,
        ml_result
    )

    risk_level = get_risk_level(
        result["hybrid_score"],
        result["rule_score"],
        result["ml_anomaly_score"]
    )

    ml_status = ml_result.get(
        "status"
    )

    return {
        **result,

        "risk_level":
            risk_level,

        "ml_status":
            ml_status,

        "explanation": (
            "Rule-based security findings "
            "remain the primary risk signal, "
            "while ML provides supporting "
            "behavioral anomaly evidence."
        )
    }