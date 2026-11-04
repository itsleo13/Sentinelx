from sklearn.ensemble import IsolationForest

from history import load_history


RISKY_PORTS = {
    21,
    23,
    135,
    139,
    445,
    3389,
    5900
}


SEVERITY_VALUES = {
    "Critical": 3,
    "High": 2,
    "Medium": 1,
    "Low": 0.5,
    "Info": 0
}


class MLAnalyzer:

    def __init__(
        self,
        contamination=0.1,
        random_state=42
    ):

        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=random_state
        )

        self.trained = False

    def extract_features(self, scan):

        open_ports = scan.get(
            "open_ports",
            []
        )

        findings = scan.get(
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

        for port in open_ports:

            if port.get("port") in RISKY_PORTS:
                risky_ports += 1

            if port.get("service") == "Unknown":
                unknown_services += 1

        for finding in findings:

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

        risk_score = scan.get(
            "risk_score",
            0
        )

        return [
            total_open_ports,
            risky_ports,
            unknown_services,
            high_risk_findings,
            medium_risk_findings,
            risk_score
        ]

    def train_from_history(
        self,
        minimum_samples=5
    ):

        history = load_history()

        if len(history) < minimum_samples:

            self.trained = False

            return {
                "trained": False,
                "samples": len(history),
                "message": (
                    "Insufficient historical "
                    "scan data for ML baseline."
                )
            }

        features = [
            self.extract_features(scan)
            for scan in history
        ]

        self.model.fit(features)

        self.trained = True

        return {
            "trained": True,
            "samples": len(history),
            "message": (
                "ML model trained from "
                "SentinelX scan history."
            )
        }

    def analyze(self, scan):

        if not self.trained:

            return {
                "status": "Unavailable",
                "prediction": None,
                "anomaly_score": None,
                "message": (
                    "ML model is not trained. "
                    "More historical scans are required."
                ),
                "features":
                    self.extract_features(scan)
            }

        features = [
            self.extract_features(scan)
        ]

        prediction = self.model.predict(
            features
        )[0]

        anomaly_score = self.model.decision_function(
            features
        )[0]

        if prediction == -1:

            status = "Anomalous"

        else:

            status = "Normal"

        return {
            "status": status,
            "prediction": int(
                prediction
            ),
            "anomaly_score": round(
                float(anomaly_score),
                4
            ),
            "message": (
                "Current scan compared "
                "against historical behavior."
            ),
            "features": {

                "total_open_ports":
                    features[0][0],

                "risky_ports":
                    features[0][1],

                "unknown_services":
                    features[0][2],

                "high_risk_findings":
                    features[0][3],

                "medium_risk_findings":
                    features[0][4],

                "risk_score":
                    features[0][5]
            }
        }


def analyze_with_history(scan):

    analyzer = MLAnalyzer()

    training_result = (
        analyzer.train_from_history()
    )

    result = analyzer.analyze(
        scan
    )

    result["training"] = training_result

    return result