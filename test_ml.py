from ml_analyzer import MLAnalyzer


# Normal-looking historical scans
training_data = [
    {
        "open_ports": [
            {"port": 80, "service": "http"},
            {"port": 443, "service": "https"}
        ],
        "findings": []
    },
    {
        "open_ports": [
            {"port": 80, "service": "http"},
            {"port": 443, "service": "https"}
        ],
        "findings": []
    },
    {
        "open_ports": [
            {"port": 80, "service": "http"},
            {"port": 443, "service": "https"},
            {"port": 8080, "service": "http-alt"}
        ],
        "findings": []
    },
    {
        "open_ports": [
            {"port": 22, "service": "ssh"},
            {"port": 80, "service": "http"},
            {"port": 443, "service": "https"}
        ],
        "findings": []
    },
    {
        "open_ports": [
            {"port": 80, "service": "http"},
            {"port": 443, "service": "https"}
        ],
        "findings": []
    }
]


# Create ML engine
ml = MLAnalyzer()

# Train model
ml.train(training_data)


# Test scan
test_scan = {
    "open_ports": [
        {"port": 23, "service": "Telnet"},
        {"port": 445, "service": "SMB"},
        {"port": 3389, "service": "RDP"},
        {"port": 5900, "service": "VNC"},
        {"port": 65000, "service": "Unknown"}
    ],

    "findings": [
        {
            "port": 23,
            "severity": "High"
        },
        {
            "port": 445,
            "severity": "Medium"
        },
        {
            "port": 3389,
            "severity": "High"
        }
    ]
}


result = ml.analyze(test_scan)

print()
print("=" * 50)
print("SENTINELX ML ANALYSIS")
print("=" * 50)

print(
    "Status         :",
    result["status"]
)

print(
    "Prediction     :",
    result["prediction"]
)

print(
    "Anomaly Score  :",
    result["anomaly_score"]
)

print(
    "Features       :"
)

for name, value in result[
    "features"
].items():

    print(
        f"  {name}: {value}"
    )
