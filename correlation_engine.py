# ============================================================
# SENTINELX ADVANCED CORRELATION ENGINE
# ============================================================

from service_risk_engine import (
    assess_host_services,
    calculate_service_risk,
    get_top_service_findings
)

from banner_intelligence import (
    analyze_host_banners
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
# MERGE OPEN PORTS
# ============================================================

def merge_open_ports(
    host_ports,
    service_ports
):

    merged = []
    seen = set()

    for item in (
        host_ports or []
    ) + (
        service_ports or []
    ):

        if isinstance(
            item,
            dict
        ):

            port = item.get(
                "port"
            )

            if port is None:
                continue

            if port in seen:
                continue

            seen.add(port)

            merged.append(
                dict(item)
            )

        elif isinstance(
            item,
            int
        ):

            if item in seen:
                continue

            seen.add(item)

            merged.append({
                "port": item
            })

    return merged


# ============================================================
# FINDING RISK
# ============================================================

def get_findings_risk(
    findings
):

    score = 0

    for finding in findings or []:

        if not isinstance(
            finding,
            dict
        ):
            continue

        severity = finding.get(
            "severity",
            "Info"
        )

        if severity == "Critical":

            score = max(
                score,
                80
            )

        elif severity == "High":

            score = max(
                score,
                60
            )

        elif severity == "Medium":

            score = max(
                score,
                30
            )

        elif severity == "Low":

            score = max(
                score,
                10
            )

    return score


# ============================================================
# BANNER SUMMARY
# ============================================================

def get_banner_statistics(
    banners
):

    total = len(
        banners or []
    )

    available = sum(
        1
        for banner in banners or []
        if banner.get(
            "banner_available",
            False
        )
    )

    identified = sum(
        1
        for banner in banners or []
        if banner.get(
            "product"
        )
    )

    versions = sum(
        1
        for banner in banners or []
        if banner.get(
            "version"
        )
    )

    high_confidence = sum(
        1
        for banner in banners or []
        if banner.get(
            "confidence"
        ) == "High"
    )

    medium_confidence = sum(
        1
        for banner in banners or []
        if banner.get(
            "confidence"
        ) == "Medium"
    )

    return {

        "total": total,

        "available": available,

        "identified": identified,

        "versions": versions,

        "high_confidence":
            high_confidence,

        "medium_confidence":
            medium_confidence
    }


# ============================================================
# CORRELATE SINGLE HOST
# ============================================================

def correlate_host(
    host,
    host_profile=None,
    service_profile=None
):

    host_profile = (
        host_profile or {}
    )

    service_profile = (
        service_profile or {}
    )

    # ========================================================
    # BASIC IDENTITY
    # ========================================================

    ip = host.get(
        "ip",
        host_profile.get(
            "ip",
            "Unknown"
        )
    )

    hostname = host_profile.get(
        "hostname",
        host.get(
            "hostname",
            "Unknown"
        )
    )

    vendor = host_profile.get(
        "vendor",
        host.get(
            "vendor",
            "Unknown"
        )
    )

    mac = host_profile.get(
        "mac",
        host.get(
            "mac",
            "Unknown"
        )
    )

    status = host_profile.get(
        "status",
        host.get(
            "status",
            "unknown"
        )
    )

    identity_confidence = (
        host_profile.get(
            "identity_confidence",
            "Low"
        )
    )

    discovery_method = (
        host_profile.get(
            "discovery_method",
            host.get(
                "discovery_method",
                "Unknown"
            )
        )
    )

    # ========================================================
    # RAW SERVICES
    # ========================================================

    raw_services = (
        service_profile.get(
            "services",
            []
        )
    )

    # ========================================================
    # SERVICE RISK
    # ========================================================

    assessed_services = (
        assess_host_services(
            raw_services
        )
    )

    service_risk = (
        calculate_service_risk(
            assessed_services
        )
    )

    # ========================================================
    # BANNER INTELLIGENCE
    # ========================================================

    banner_results = (
        analyze_host_banners(
            raw_services
        )
    )

    banner_statistics = (
        get_banner_statistics(
            banner_results
        )
    )

    # ========================================================
    # OPEN PORTS
    # ========================================================

    host_ports = (
        host_profile.get(
            "open_ports",
            []
        )
    )

    service_ports = (
        service_profile.get(
            "open_ports",
            []
        )
    )

    open_ports = merge_open_ports(
        host_ports,
        service_ports
    )

    # ========================================================
    # FINDINGS
    # ========================================================

    findings = (
        host_profile.get(
            "findings",
            []
        )
    )

    finding_risk = (
        get_findings_risk(
            findings
        )
    )

    # ========================================================
    # PROFILE RISK
    # ========================================================

    profile_risk = (
        host_profile.get(
            "risk_score",
            0
        )
    )

    # ========================================================
    # UNIFIED RISK
    #
    # Important:
    # Banner detection alone does NOT increase risk.
    # A banner is evidence/intelligence, not proof
    # of a vulnerability.
    # ========================================================

    unified_risk = max(
        profile_risk,
        service_risk,
        finding_risk
    )

    # ========================================================
    # TOP SERVICE FINDINGS
    # ========================================================

    top_service_findings = (
        get_top_service_findings(
            assessed_services
        )
    )

    # ========================================================
    # RESULT
    # ========================================================

    return {

        "ip":
            ip,

        "hostname":
            hostname,

        "mac":
            mac,

        "vendor":
            vendor,

        "status":
            status,

        "identity_confidence":
            identity_confidence,

        "discovery_method":
            discovery_method,

        # ----------------------------------------------------
        # Ports
        # ----------------------------------------------------

        "open_ports":
            open_ports,

        "open_port_count":
            len(open_ports),

        # ----------------------------------------------------
        # Services
        # ----------------------------------------------------

        "services":
            assessed_services,

        "service_count":
            len(assessed_services),

        # ----------------------------------------------------
        # Banners
        # ----------------------------------------------------

        "banners":
            banner_results,

        "banner_count":
            banner_statistics[
                "total"
            ],

        "banners_available":
            banner_statistics[
                "available"
            ],

        "products_identified":
            banner_statistics[
                "identified"
            ],

        "versions_identified":
            banner_statistics[
                "versions"
            ],

        "banner_high_confidence":
            banner_statistics[
                "high_confidence"
            ],

        "banner_medium_confidence":
            banner_statistics[
                "medium_confidence"
            ],

        # ----------------------------------------------------
        # Findings
        # ----------------------------------------------------

        "findings":
            findings,

        "finding_count":
            len(findings),

        # ----------------------------------------------------
        # Risk components
        # ----------------------------------------------------

        "profile_risk":
            profile_risk,

        "service_risk":
            service_risk,

        "finding_risk":
            finding_risk,

        "risk_score":
            unified_risk,

        "risk_level":
            get_risk_level(
                unified_risk
            ),

        # ----------------------------------------------------
        # Intelligence
        # ----------------------------------------------------

        "top_service_findings":
            top_service_findings
    }


# ============================================================
# CORRELATE NETWORK
# ============================================================

def correlate_network(
    hosts,
    host_profiles=None,
    service_profiles=None
):

    host_profiles = (
        host_profiles or []
    )

    service_profiles = (
        service_profiles or []
    )

    # ========================================================
    # INDEX BY IP
    # ========================================================

    host_map = {

        item.get("ip"): item

        for item in host_profiles

        if item.get("ip")
    }

    service_map = {

        item.get("ip"): item

        for item in service_profiles

        if item.get("ip")
    }

    correlated_hosts = []

    # ========================================================
    # CORRELATE HOSTS
    # ========================================================

    for host in hosts:

        ip = host.get(
            "ip",
            "Unknown"
        )

        profile = host_map.get(
            ip,
            {}
        )

        services = service_map.get(
            ip,
            {}
        )

        correlated = correlate_host(
            host,
            profile,
            services
        )

        correlated_hosts.append(
            correlated
        )

    # ========================================================
    # NETWORK STATISTICS
    # ========================================================

    total_hosts = len(
        correlated_hosts
    )

    active_hosts = sum(
        1
        for host in correlated_hosts
        if host.get(
            "status"
        ) == "up"
    )

    total_ports = sum(
        host.get(
            "open_port_count",
            0
        )
        for host in correlated_hosts
    )

    total_services = sum(
        host.get(
            "service_count",
            0
        )
        for host in correlated_hosts
    )

    total_banners = sum(
        host.get(
            "banners_available",
            0
        )
        for host in correlated_hosts
    )

    total_products = sum(
        host.get(
            "products_identified",
            0
        )
        for host in correlated_hosts
    )

    total_findings = sum(
        host.get(
            "finding_count",
            0
        )
        for host in correlated_hosts
    )

    # ========================================================
    # RISK DISTRIBUTION
    # ========================================================

    critical = sum(
        1
        for host in correlated_hosts
        if host.get(
            "risk_level"
        ) == "Critical"
    )

    high = sum(
        1
        for host in correlated_hosts
        if host.get(
            "risk_level"
        ) == "High"
    )

    medium = sum(
        1
        for host in correlated_hosts
        if host.get(
            "risk_level"
        ) == "Medium"
    )

    low = sum(
        1
        for host in correlated_hosts
        if host.get(
            "risk_level"
        ) == "Low"
    )

    info = sum(
        1
        for host in correlated_hosts
        if host.get(
            "risk_level"
        ) == "Info"
    )

    # ========================================================
    # NETWORK SCORE
    # ========================================================

    network_score = 0

    for host in correlated_hosts:

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

        "hosts":
            correlated_hosts,

        "total_hosts":
            total_hosts,

        "active_hosts":
            active_hosts,

        "total_open_ports":
            total_ports,

        "total_services":
            total_services,

        "total_banners":
            total_banners,

        "total_products":
            total_products,

        "total_findings":
            total_findings,

        "critical_hosts":
            critical,

        "high_risk_hosts":
            high,

        "medium_risk_hosts":
            medium,

        "low_risk_hosts":
            low,

        "info_hosts":
            info,

        "network_risk_score":
            network_score,

        "network_risk":
            get_risk_level(
                network_score
            )
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
            -host.get(
                "service_count",
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

            item["host_ip"] = (
                host.get(
                    "ip",
                    "Unknown"
                )
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
# PRINT CORRELATION REPORT
# ============================================================

def print_correlation_report(
    result
):

    print()

    print("=" * 72)
    print("ADVANCED SECURITY CORRELATION")
    print("=" * 72)

    print(
        f"Network Risk      : "
        f"{result.get('network_risk', 'Info')}"
    )

    print(
        f"Network Score     : "
        f"{result.get('network_risk_score', 0)}/100"
    )

    print(
        f"Hosts             : "
        f"{result.get('total_hosts', 0)}"
    )

    print(
        f"Open Ports        : "
        f"{result.get('total_open_ports', 0)}"
    )

    print(
        f"Services          : "
        f"{result.get('total_services', 0)}"
    )

    print(
        f"Banners           : "
        f"{result.get('total_banners', 0)}"
    )

    print(
        f"Products          : "
        f"{result.get('total_products', 0)}"
    )

    print(
        f"Findings          : "
        f"{result.get('total_findings', 0)}"
    )

    print()

    print("Risk Distribution:")

    print(
        f"  Critical : "
        f"{result.get('critical_hosts', 0)}"
    )

    print(
        f"  High     : "
        f"{result.get('high_risk_hosts', 0)}"
    )

    print(
        f"  Medium   : "
        f"{result.get('medium_risk_hosts', 0)}"
    )

    print(
        f"  Low      : "
        f"{result.get('low_risk_hosts', 0)}"
    )

    print(
        f"  Info     : "
        f"{result.get('info_hosts', 0)}"
    )

    # ========================================================
    # HOST DETAILS
    # ========================================================

    print()
    print("-" * 72)
    print("HOST INTELLIGENCE")
    print("-" * 72)

    top_hosts = get_top_network_hosts(
        result
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

            print()

            print(
                f"{index}. "
                f"{host.get('ip', 'Unknown')}"
            )

            print(
                f"  Identity    : "
                f"{host.get('hostname', 'Unknown')}"
            )

            print(
                f"  Vendor      : "
                f"{host.get('vendor', 'Unknown')}"
            )

            print(
                f"  Confidence  : "
                f"{host.get('identity_confidence', 'Low')}"
            )

            print(
                f"  Ports       : "
                f"{host.get('open_port_count', 0)}"
            )

            print(
                f"  Services    : "
                f"{host.get('service_count', 0)}"
            )

            print(
                f"  Banners     : "
                f"{host.get('banners_available', 0)}/"
                f"{host.get('banner_count', 0)}"
            )

            print(
                f"  Products    : "
                f"{host.get('products_identified', 0)}"
            )

            print(
                f"  Findings    : "
                f"{host.get('finding_count', 0)}"
            )

            print(
                f"  Profile Risk: "
                f"{host.get('profile_risk', 0)}/100"
            )

            print(
                f"  Service Risk: "
                f"{host.get('service_risk', 0)}/100"
            )

            print(
                f"  Finding Risk: "
                f"{host.get('finding_risk', 0)}/100"
            )

            print(
                f"  Final Risk  : "
                f"{host.get('risk_level', 'Info')} "
                f"({host.get('risk_score', 0)}/100)"
            )

            # ------------------------------------------------
            # Services
            # ------------------------------------------------

            for service in host.get(
                "services",
                []
            ):

                print(
                    f"    └─ "
                    f"{service.get('port', '?')}/"
                    f"{service.get('protocol', 'TCP')} "
                    f"{service.get('service', 'Unknown')} "
                    f"[{service.get('severity', 'Info')}]"
                )

            # ------------------------------------------------
            # Banners
            # ------------------------------------------------

            for banner in host.get(
                "banners",
                []
            ):

                if not banner.get(
                    "banner_available"
                ):
                    continue

                print(
                    f"       Banner    : "
                    f"{banner.get('server') or 'Unknown'}"
                )

                print(
                    f"       Product   : "
                    f"{banner.get('product') or 'Unknown'}"
                )

                print(
                    f"       Version   : "
                    f"{banner.get('version') or 'Unknown'}"
                )

                print(
                    f"       Confidence: "
                    f"{banner.get('confidence', 'Low')}"
                )

    # ========================================================
    # TOP SERVICES
    # ========================================================

    print()
    print("-" * 72)
    print("TOP SERVICE FINDINGS")
    print("-" * 72)

    top_services = (
        get_top_network_services(
            result
        )
    )

    if not top_services:

        print(
            "No services detected."
        )

    else:

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