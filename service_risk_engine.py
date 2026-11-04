# ============================================================
# SENTINELX SERVICE RISK ENGINE
# ============================================================

SERVICE_RULES = {

    21: {
        "service": "FTP",
        "severity": "Medium",
        "risk_score": 30,
        "evidence": "FTP service is exposed on TCP port 21.",
        "recommendation":
            "Prefer SFTP/FTPS and restrict FTP exposure."
    },

    22: {
        "service": "SSH",
        "severity": "Info",
        "risk_score": 0,
        "evidence": "SSH service is exposed on TCP port 22.",
        "recommendation":
            "Use strong authentication and restrict SSH access."
    },

    23: {
        "service": "Telnet",
        "severity": "High",
        "risk_score": 60,
        "evidence": "Telnet service is exposed on TCP port 23.",
        "recommendation":
            "Replace Telnet with SSH."
    },

    25: {
        "service": "SMTP",
        "severity": "Low",
        "risk_score": 10,
        "evidence": "SMTP service is exposed on TCP port 25.",
        "recommendation":
            "Restrict mail-service exposure and verify relay configuration."
    },

    53: {
        "service": "DNS",
        "severity": "Info",
        "risk_score": 0,
        "evidence": "DNS service is exposed on TCP port 53.",
        "recommendation":
            "Verify that DNS exposure is intentional and restrict access where appropriate."
    },

    80: {
        "service": "HTTP",
        "severity": "Info",
        "risk_score": 0,
        "evidence": "HTTP service is exposed on TCP port 80.",
        "recommendation":
            "Verify the web service is intentionally exposed and keep it patched."
    },

    110: {
        "service": "POP3",
        "severity": "Low",
        "risk_score": 10,
        "evidence": "POP3 service is exposed on TCP port 110.",
        "recommendation":
            "Prefer encrypted mail protocols such as POP3S."
    },

    135: {
        "service": "MS RPC",
        "severity": "Medium",
        "risk_score": 30,
        "evidence": "MS RPC service is exposed on TCP port 135.",
        "recommendation":
            "Restrict RPC exposure to trusted networks."
    },

    139: {
        "service": "NetBIOS",
        "severity": "Medium",
        "risk_score": 30,
        "evidence": "NetBIOS service is exposed on TCP port 139.",
        "recommendation":
            "Restrict legacy file-sharing protocols."
    },

    143: {
        "service": "IMAP",
        "severity": "Low",
        "risk_score": 10,
        "evidence": "IMAP service is exposed on TCP port 143.",
        "recommendation":
            "Prefer encrypted IMAPS connections."
    },

    443: {
        "service": "HTTPS",
        "severity": "Info",
        "risk_score": 0,
        "evidence": "HTTPS service is exposed on TCP port 443.",
        "recommendation":
            "Verify TLS configuration and keep the web service patched."
    },

    445: {
        "service": "SMB",
        "severity": "Medium",
        "risk_score": 30,
        "evidence": "SMB service is exposed on TCP port 445.",
        "recommendation":
            "Restrict SMB exposure and keep the host patched."
    },

    3389: {
        "service": "RDP",
        "severity": "High",
        "risk_score": 60,
        "evidence": "RDP service is exposed on TCP port 3389.",
        "recommendation":
            "Restrict RDP and require strong authentication."
    },

    5900: {
        "service": "VNC",
        "severity": "High",
        "risk_score": 60,
        "evidence": "VNC service is exposed on TCP port 5900.",
        "recommendation":
            "Restrict VNC and use secure remote access."
    }
}


DEFAULT_RULE = {
    "service": "Unknown",
    "severity": "Info",
    "risk_score": 0,
    "evidence": "A TCP service was detected.",
    "recommendation":
        "Verify that the service is intentionally exposed."
}


# ============================================================
# SERVICE ASSESSMENT
# ============================================================

def assess_service(service):

    port = service.get(
        "port"
    )

    rule = SERVICE_RULES.get(
        port,
        DEFAULT_RULE
    )

    service_name = service.get(
        "service"
    )

    if not service_name:
        service_name = rule["service"]

    return {
        "port": port,

        "protocol": service.get(
            "protocol",
            "TCP"
        ),

        "service": service_name,

        "state": service.get(
            "state",
            "open"
        ),

        "severity": rule["severity"],

        "risk_score": rule["risk_score"],

        "evidence": rule["evidence"],

        "recommendation":
            rule["recommendation"],

        "banner": service.get(
            "banner"
        ),

        "latency_ms": service.get(
            "latency_ms"
        )
    }


# ============================================================
# HOST SERVICE ASSESSMENT
# ============================================================

def assess_host_services(
    services
):

    assessed = []

    for service in services:

        if not isinstance(
            service,
            dict
        ):
            continue

        assessed.append(
            assess_service(
                service
            )
        )

    return assessed


# ============================================================
# HOST RISK
# ============================================================

def calculate_service_risk(
    assessed_services
):

    if not assessed_services:
        return 0

    return max(
        service.get(
            "risk_score",
            0
        )
        for service in assessed_services
    )


# ============================================================
# TOP SERVICE FINDINGS
# ============================================================

def get_top_service_findings(
    assessed_services,
    limit=5
):

    return sorted(
        assessed_services,
        key=lambda service: (
            -service.get(
                "risk_score",
                0
            ),
            service.get(
                "port",
                0
            )
        )
    )[:limit]


# ============================================================
# NETWORK SERVICE ASSESSMENT
# ============================================================

def assess_network_services(
    service_profiles
):

    results = []

    for host in service_profiles:

        ip = host.get(
            "ip",
            "Unknown"
        )

        services = host.get(
            "services",
            []
        )

        assessed = (
            assess_host_services(
                services
            )
        )

        risk_score = (
            calculate_service_risk(
                assessed
            )
        )

        results.append({

            "ip": ip,

            "hostname": host.get(
                "hostname",
                "Unknown"
            ),

            "vendor": host.get(
                "vendor",
                "Unknown"
            ),

            "services": assessed,

            "service_count": len(
                assessed
            ),

            "risk_score": risk_score,

            "top_findings":
                get_top_service_findings(
                    assessed
                )
        })

    return results


# ============================================================
# PRINT SERVICE RISK
# ============================================================

def print_service_risk(
    results
):

    print()
    print("=" * 72)
    print("SERVICE RISK INTELLIGENCE")
    print("=" * 72)

    if not results:

        print(
            "No service information available."
        )

        return

    for host in results:

        print()
        print(
            f"Host: "
            f"{host.get('ip', 'Unknown')}"
        )

        print(
            f"Hostname: "
            f"{host.get('hostname', 'Unknown')}"
        )

        print(
            f"Risk Score: "
            f"{host.get('risk_score', 0)}/100"
        )

        if not host.get(
            "services"
        ):

            print(
                "  No services detected."
            )

            continue

        for service in host[
            "services"
        ]:

            print(
                f"  [{service.get('severity', 'Info')}] "
                f"{service.get('port')} "
                f"{service.get('service')}"
            )

            print(
                f"       Evidence: "
                f"{service.get('evidence')}"
            )

            print(
                f"       Action: "
                f"{service.get('recommendation')}"
            )