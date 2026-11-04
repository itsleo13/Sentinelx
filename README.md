# SentinelX - AI-Powered Network Security Scanner & Profiler

SentinelX is an advanced, modular network reconnaissance and intelligence scanner. Beyond standard TCP port scanning, SentinelX integrates machine learning models, banner intelligence, automated rule engines, and correlation analysis to deliver real-time service risk profiles and actionable security insights.

---

## Key Features

- **Fast TCP Discovery:** High-speed network port enumeration and active host discovery.
- **Banner Intelligence:** In-depth service fingerprinting and version reconnaissance.
- **Machine Learning Profiler:** Predictive service analysis and automated anomaly classification (`ml_analyzer`, `host_ml_engine`).
- **Heuristic Rule & Risk Engine:** Severity scoring and risk classification per detected service.
- **State Change Detection:** Tracks differences across consecutive scans against target environments.
- **Executive Reporting & Dashboard:** Detailed scan logs and automated dashboard report generation.

---

## Architecture Overview

```text
SentinelX/
├── scanner.py                 # Core scan orchestrator
├── discovery.py               # Host and network discovery
├── services.py                # Known port-to-service mapping
├── banner_intelligence.py     # Service banner retrieval & parsing
├── host_profiler.py           # Host fingerprinting engine
├── host_ml_engine.py          # Machine learning classification
├── correlation_engine.py      # Cross-service alert correlation
├── rule_engine.py             # Security rule validation
├── service_risk_engine.py     # Risk and severity scoring
├── change_detector.py         # Historical state tracking
├── report_dashboard.py        # Scan reporting and exports
└── config.py                  # Global scanner configuration
