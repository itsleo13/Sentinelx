from datetime import datetime

from service_risk_engine import (
    assess_host_services,
    calculate_service_risk,
    get_top_service_findings
)


# ============================================================
# RISK LEVEL
# ============================================================

def get_risk_level(score):

    if score >= 80:
        return "Critical"

    if score >= 60:
        return "High"

    if score >= 30:
        return "Medium"

    if score > 0:
        return "Low"

    return "Info"


# ============================================================
# HOST ANALYSIS
# ============================================================

def analyze_host(
    host_profile,
    service_profile=None
):

    service_profile = service_profile or {}

    ip = host_profile.get(
        "ip",
        "Unknown"
    )

    services = service_profile.get(
        "services",
        []
    )

    service_ports = service_profile.get(
        "open_ports",
        []
    )

    host_ports = host_profile.get(
        "open_ports",
        []
    )

    findings = host_profile.get(
        "findings",
        []
    )

    risk_score = host_profile.get(
        "risk_score",
        0
    )

    # ========================================================
    # SERVICE RISK INTELLIGENCE
    # ========================================================

    assessed_services = assess_host_services(
        services
    )

    service_risk = calculate_service_risk(
        assessed_services
    )

    risk_score = max(
        risk_score,
        service_risk
    )

    # ========================================================
    # MERGE OPEN PORTS
    # ========================================================

    merged_ports = []
    seen_ports = set()

    for port_data in (
        host_ports + service_ports
    ):

        if isinstance(
            port_data,
            dict
        ):

            port = port_data.get(
                "port"
            )

            if port is None:
                continue

            if port not in seen_ports:

                seen_ports.add(
                    port
                )

                merged_ports.append(
                    port_data
                )

        elif isinstance(
            port_data,
            int
        ):

            if port_data not in seen_ports:

                seen_ports.add(
                    port_data
                )

                merged_ports.append({
                    "port": port_data
                })

    # ========================================================
    # EXISTING FINDINGS RISK
    # ========================================================

    for finding in findings:

        severity = finding.get(
            "severity",
            "Info"
        )

        if severity == "Critical":

            risk_score = max(
                risk_score,
                80
            )

        elif severity == "High":

            risk_score = max(
                risk_score,
                60
            )

        elif severity == "Medium":

            risk_score = max(
                risk_score,
                30
            )

        elif severity == "Low":

            risk_score = max(
                risk_score,
                10
            )

    # ========================================================
    # CORRELATED HOST
    # ========================================================

    return {

        "ip": ip,

        "device_name": host_profile.get(
            "device_name",
            host_profile.get(
                "hostname",
                "Unknown"
            )
        ),

        "hostname": host_profile.get(
            "hostname",
            "Unknown"
        ),

        "mac": host_profile.get(
            "mac",
            "Unknown"
        ),

        "vendor": host_profile.get(
            "vendor",
            "Unknown"
        ),

        "status": host_profile.get(
            "status",
            "unknown"
        ),

        "confidence": host_profile.get(
            "identity_confidence",
            "Low"
        ),

        "discovery_method": host_profile.get(
            "discovery_method",
            "Unknown"
        ),

        "open_ports": merged_ports,

        "services": assessed_services,

        "service_count": len(
            assessed_services
        ),

        "service_risk": service_risk,

        "findings": findings,

        "risk_score": risk_score,

        "risk_level": get_risk_level(
            risk_score
        ),

        "top_service_findings":
            get_top_service_findings(
                assessed_services
            )
    }


# ============================================================
# NETWORK ANALYSIS
# ============================================================

def analyze_network(
    hosts,
    host_profiles=None,
    service_profiles=None
):

    host_profiles = host_profiles or []
    service_profiles = service_profiles or []

    # ========================================================
    # INDEX PROFILES BY IP
    # ========================================================

    host_map = {
        host.get("ip"): host
        for host in host_profiles
        if host.get("ip")
    }

    service_map = {
        host.get("ip"): host
        for host in service_profiles
        if host.get("ip")
    }

    analyzed_hosts = []

    # ========================================================
    # CORRELATE BY IP
    # ========================================================

    for host in hosts:

        ip = host.get(
            "ip",
            "Unknown"
        )

        base_profile = host_map.get(
            ip,
            host
        )

        service_profile = service_map.get(
            ip,
            {}
        )

        correlated_host = analyze_host(
            base_profile,
            service_profile
        )

        analyzed_hosts.append(
            correlated_host
        )

    # ========================================================
    # NETWORK STATISTICS
    # ========================================================

    total_hosts = len(
        analyzed_hosts
    )

    active_hosts = sum(
        1
        for host in analyzed_hosts
        if host.get("status") == "up"
    )

    total_open_ports = sum(
        len(
            host.get(
                "open_ports",
                []
            )
        )
        for host in analyzed_hosts
    )

    total_services = sum(
        host.get(
            "service_count",
            0
        )
        for host in analyzed_hosts
    )

    total_findings = sum(
        len(
            host.get(
                "findings",
                []
            )
        )
        for host in analyzed_hosts
    )

    critical_hosts = sum(
        1
        for host in analyzed_hosts
        if host.get(
            "risk_level"
        ) == "Critical"
    )

    high_hosts = sum(
        1
        for host in analyzed_hosts
        if host.get(
            "risk_level"
        ) == "High"
    )

    medium_hosts = sum(
        1
        for host in analyzed_hosts
        if host.get(
            "risk_level"
        ) == "Medium"
    )

    low_hosts = sum(
        1
        for host in analyzed_hosts
        if host.get(
            "risk_level"
        ) == "Low"
    )

    info_hosts = sum(
        1
        for host in analyzed_hosts
        if host.get(
            "risk_level"
        ) == "Info"
    )

    # ========================================================
    # NETWORK RISK SCORE
    # ========================================================

    network_score = 0

    for host in analyzed_hosts:

        network_score = max(
            network_score,
            host.get(
                "risk_score",
                0
            )
        )

    # ========================================================
    # NETWORK RESULT
    # ========================================================

    return {

        "generated_at":
            datetime.now().isoformat(
                timespec="seconds"
            ),

        "total_hosts":
            total_hosts,

        "active_hosts":
            active_hosts,

        "total_open_ports":
            total_open_ports,

        "total_services":
            total_services,

        "total_findings":
            total_findings,

        "critical_hosts":
            critical_hosts,

        "high_risk_hosts":
            high_hosts,

        "medium_risk_hosts":
            medium_hosts,

        "low_risk_hosts":
            low_hosts,

        "info_hosts":
            info_hosts,

        "network_risk_score":
            network_score,

        "network_risk":
            get_risk_level(
                network_score
            ),

        "hosts":
            analyzed_hosts
    }


# ============================================================
# TOP NETWORK HOSTS
# ============================================================

def get_top_network_hosts(
    analysis,
    limit=5
):

    hosts = analysis.get(
        "hosts",
        []
    )

    return sorted(
        hosts,
        key=lambda host: (
            -host.get(
                "risk_score",
                0
            ),
            host.get(
                "ip",
                ""
            )
        )
    )[:limit]


# ============================================================
# TOP NETWORK SERVICES
# ============================================================

def get_top_network_services(
    analysis,
    limit=10
):

    services = []

    for host in analysis.get(
        "hosts",
        []
    ):

        for service in host.get(
            "services",
            []
        ):

            item = dict(
                service
            )

            item["host_ip"] = host.get(
                "ip",
                "Unknown"
            )

            services.append(
                item
            )

    return sorted(
        services,
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
# PRINT NETWORK ANALYSIS
# ============================================================

def print_network_analysis(
    analysis
):

    print()

    print("=" * 72)
    print("NETWORK SECURITY INTELLIGENCE")
    print("=" * 72)

    print(
        f"Network Risk      : "
        f"{analysis.get('network_risk', 'Info')}"
    )

    print(
        f"Network Score     : "
        f"{analysis.get('network_risk_score', 0)}/100"
    )

    print(
        f"Hosts Discovered  : "
        f"{analysis.get('total_hosts', 0)}"
    )

    print(
        f"Active Hosts      : "
        f"{analysis.get('active_hosts', 0)}"
    )

    print(
        f"Open Ports        : "
        f"{analysis.get('total_open_ports', 0)}"
    )

    print(
        f"Services          : "
        f"{analysis.get('total_services', 0)}"
    )

    print(
        f"Findings          : "
        f"{analysis.get('total_findings', 0)}"
    )

    print()

    print("Risk Distribution:")
    print(
        f"  Critical : "
        f"{analysis.get('critical_hosts', 0)}"
    )

    print(
        f"  High     : "
        f"{analysis.get('high_risk_hosts', 0)}"
    )

    print(
        f"  Medium   : "
        f"{analysis.get('medium_risk_hosts', 0)}"
    )

    print(
        f"  Low      : "
        f"{analysis.get('low_risk_hosts', 0)}"
    )

    print(
        f"  Info     : "
        f"{analysis.get('info_hosts', 0)}"
    )

    # ========================================================
    # TOP HOSTS
    # ========================================================

    print()
    print("-" * 72)
    print("TOP HOSTS")
    print("-" * 72)

    top_hosts = get_top_network_hosts(
        analysis
    )

    if not top_hosts:

        print(
            "No hosts available."
        )

    else:

        for index, host in enumerate(
            top_hosts,
            start=1
        ):

            print(
                f"{index}. "
                f"{host.get('ip', 'Unknown')}"
            )

            print(
                f"   Device     : "
                f"{host.get('device_name', 'Unknown')}"
            )

            print(
                f"   Vendor     : "
                f"{host.get('vendor', 'Unknown')}"
            )

            print(
                f"   Open Ports : "
                f"{len(host.get('open_ports', []))}"
            )

            print(
                f"   Services   : "
                f"{host.get('service_count', 0)}"
            )

            print(
                f"   Risk       : "
                f"{host.get('risk_level', 'Info')} "
                f"({host.get('risk_score', 0)}/100)"
            )

            print()

    # ========================================================
    # TOP SERVICES
    # ========================================================

    print("-" * 72)
    print("TOP SERVICE FINDINGS")
    print("-" * 72)

    top_services = get_top_network_services(
        analysis
    )

    if not top_services:

        print(
            "No services detected."
        )

        return

    for index, service in enumerate(
        top_services,
        start=1
    ):

        print(
            f"{index}. "
            f"{service.get('host_ip', 'Unknown')}:"
            f"{service.get('port', 'Unknown')} "
            f"{service.get('service', 'Unknown')}"
        )

        print(
            f"   Severity : "
            f"{service.get('severity', 'Info')}"
        )

        print(
            f"   Risk     : "
            f"{service.get('risk_score', 0)}/100"
        )

        print(
            f"   Evidence : "
            f"{service.get('evidence', 'None')}"
        )

        print(
            f"   Action   : "
            f"{service.get('recommendation', 'None')}"
        )

        print()