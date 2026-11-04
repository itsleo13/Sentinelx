import socket
import ipaddress
from datetime import datetime


# ============================================================
# HOSTNAME
# ============================================================

def resolve_hostname(ip):
    """
    Resolve hostname using reverse DNS.
    """

    try:
        hostname = socket.gethostbyaddr(ip)[0]

        if hostname:
            return {
                "hostname": hostname,
                "source": "reverse_dns",
                "confidence": "High"
            }

    except (
        socket.herror,
        socket.gaierror,
        OSError
    ):
        pass

    return {
        "hostname": "Unknown",
        "source": None,
        "confidence": "Low"
    }


# ============================================================
# MAC NORMALIZATION
# ============================================================

def normalize_mac(mac):

    if not mac:
        return "Unknown"

    return mac.lower()


# ============================================================
# VENDOR
# ============================================================

def get_vendor(mac):
    """
    Placeholder for offline OUI database.

    Vendor detection will be added separately.
    """

    if not mac:
        return "Unknown"

    return "Unknown"


# ============================================================
# HOST IDENTITY
# ============================================================

def build_identity(host):

    ip = host.get(
        "ip",
        "Unknown"
    )

    mac = normalize_mac(
        host.get("mac")
    )

    hostname_info = resolve_hostname(
        ip
    )

    vendor = host.get(
        "vendor"
    )

    if not vendor:
        vendor = get_vendor(
            mac
        )

    return {

        "ip":
            ip,

        "mac":
            mac,

        "hostname":
            hostname_info["hostname"],

        "hostname_source":
            hostname_info["source"],

        "vendor":
            vendor,

        "identity_confidence":
            hostname_info["confidence"]

    }


# ============================================================
# HOST PROFILE
# ============================================================

def build_host_profile(host):

    identity = build_identity(
        host
    )

    return {

        "ip":
            identity["ip"],

        "mac":
            identity["mac"],

        "hostname":
            identity["hostname"],

        "hostname_source":
            identity["hostname_source"],

        "vendor":
            identity["vendor"],

        "status":
            host.get(
                "status",
                "up"
            ),

        "discovery_method":
            host.get(
                "discovery_method",
                "Unknown"
            ),

        "discovery_time":
            host.get(
                "discovery_time"
            ),

        "identity_confidence":
            identity[
                "identity_confidence"
            ],

        "open_ports":
            host.get(
                "open_ports",
                []
            ),

        "findings":
            host.get(
                "findings",
                []
            ),

        "risk_score":
            host.get(
                "risk_score",
                0
            )

    }


# ============================================================
# PROFILE MULTIPLE HOSTS
# ============================================================

def profile_hosts(hosts):

    profiles = []

    seen = set()

    for host in hosts:

        ip = host.get(
            "ip"
        )

        if not ip:
            continue

        if ip in seen:
            continue

        seen.add(ip)

        profiles.append(
            build_host_profile(
                host
            )
        )

    profiles.sort(
        key=lambda host:
            ipaddress.ip_address(
                host["ip"]
            )
    )

    return profiles


# ============================================================
# HOST RISK
# ============================================================

def calculate_host_risk(
    profile
):

    risk = 0

    for finding in profile.get(
        "findings",
        []
    ):

        severity = finding.get(
            "severity",
            "Info"
        )

        if severity == "Critical":
            risk += 50

        elif severity == "High":
            risk += 30

        elif severity == "Medium":
            risk += 15

        elif severity == "Low":
            risk += 5

    return min(
        risk,
        100
    )


# ============================================================
# ENRICH PROFILE
# ============================================================

def enrich_host_profile(
    profile
):

    profile["risk_score"] = (
        calculate_host_risk(
            profile
        )
    )

    open_ports = profile.get(
        "open_ports",
        []
    )

    profile["open_port_count"] = len(
        open_ports
    )

    profile["finding_count"] = len(
        profile.get(
            "findings",
            []
        )
    )

    if profile["risk_score"] >= 70:

        profile["risk_level"] = "Critical"

    elif profile["risk_score"] >= 40:

        profile["risk_level"] = "High"

    elif profile["risk_score"] >= 15:

        profile["risk_level"] = "Medium"

    elif profile["risk_score"] > 0:

        profile["risk_level"] = "Low"

    else:

        profile["risk_level"] = "Info"

    return profile


# ============================================================
# FULL HOST PROFILING
# ============================================================

def generate_host_profiles(
    hosts
):

    profiles = profile_hosts(
        hosts
    )

    enriched = []

    for profile in profiles:

        enriched.append(
            enrich_host_profile(
                profile
            )
        )

    return enriched


# ============================================================
# NETWORK SUMMARY
# ============================================================

def summarize_host_profiles(
    profiles
):

    total = len(
        profiles
    )

    critical = 0
    high = 0
    medium = 0
    low = 0
    info = 0

    total_open_ports = 0
    total_findings = 0

    for profile in profiles:

        level = profile.get(
            "risk_level",
            "Info"
        )

        if level == "Critical":
            critical += 1

        elif level == "High":
            high += 1

        elif level == "Medium":
            medium += 1

        elif level == "Low":
            low += 1

        else:
            info += 1

        total_open_ports += profile.get(
            "open_port_count",
            0
        )

        total_findings += profile.get(
            "finding_count",
            0
        )

    if critical > 0:
        network_risk = "Critical"

    elif high > 0:
        network_risk = "High"

    elif medium > 0:
        network_risk = "Medium"

    elif low > 0:
        network_risk = "Low"

    else:
        network_risk = "Info"

    return {

        "total_hosts":
            total,

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

        "total_open_ports":
            total_open_ports,

        "total_findings":
            total_findings,

        "network_risk":
            network_risk,

        "generated_at":
            datetime.now().isoformat(
                timespec="seconds"
            )

    }


# ============================================================
# DISPLAY
# ============================================================

def print_host_profiles(
    profiles
):

    print()

    print("=" * 72)
    print("HOST PROFILES")
    print("=" * 72)

    if not profiles:

        print(
            "No host profiles available."
        )

        return

    for index, profile in enumerate(
        profiles,
        start=1
    ):

        print()

        print(
            f"[{index}] "
            f"{profile['ip']}"
        )

        print(
            f"    Device Name : "
            f"{profile['hostname']}"
        )

        print(
            f"    Name Source : "
            f"{profile['hostname_source'] or 'Unknown'}"
        )

        print(
            f"    MAC         : "
            f"{profile['mac']}"
        )

        print(
            f"    Vendor      : "
            f"{profile['vendor']}"
        )

        print(
            f"    Status      : "
            f"{profile['status']}"
        )

        print(
            f"    Confidence  : "
            f"{profile['identity_confidence']}"
        )

        print(
            f"    Discovery   : "
            f"{profile['discovery_method']}"
        )

        print(
            f"    Open Ports  : "
            f"{profile['open_port_count']}"
        )

        print(
            f"    Findings    : "
            f"{profile['finding_count']}"
        )

        print(
            f"    Risk        : "
            f"{profile['risk_level']} "
            f"({profile['risk_score']}/100)"
        )