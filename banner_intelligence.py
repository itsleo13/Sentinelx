# ============================================================
# SENTINELX BANNER INTELLIGENCE
# ============================================================

import re


# ============================================================
# VERSION PATTERNS
# ============================================================

VERSION_PATTERNS = [

    (
        "apache",
        re.compile(
            r"Apache[/\s]+([0-9][\w.\-]*)",
            re.IGNORECASE
        )
    ),

    (
        "nginx",
        re.compile(
            r"nginx[/\s]+([0-9][\w.\-]*)",
            re.IGNORECASE
        )
    ),

    (
        "openssh",
        re.compile(
            r"OpenSSH[_/\s]+([0-9][\w.\-]*)",
            re.IGNORECASE
        )
    ),

    (
        "python",
        re.compile(
            r"Python[/\s]+([0-9][\w.\-]*)",
            re.IGNORECASE
        )
    ),

    (
        "iis",
        re.compile(
            r"Microsoft-IIS[/\s]+([0-9][\w.\-]*)",
            re.IGNORECASE
        )
    ),

    (
        "vsftpd",
        re.compile(
            r"vsftpd[/\s]+([0-9][\w.\-]*)",
            re.IGNORECASE
        )
    ),

    (
        "proftpd",
        re.compile(
            r"ProFTPD[/\s]+([0-9][\w.\-]*)",
            re.IGNORECASE
        )
    )
]


# ============================================================
# BANNER CLASSIFICATION
# ============================================================

def classify_banner(
    banner
):

    if not banner:

        return {
            "available": False,
            "raw": None,
            "server": None,
            "version": None,
            "product": None,
            "confidence": "Low"
        }

    text = str(
        banner
    ).strip()

    server = None
    product = None
    version = None

    # --------------------------------------------------------
    # Server header
    # --------------------------------------------------------

    match = re.search(
        r"(?:^|\s)Server:\s*([^\r\n]+)",
        text,
        re.IGNORECASE
    )

    if match:

        server = (
            match.group(1)
            .strip()
        )

    # --------------------------------------------------------
    # Version/product extraction
    # --------------------------------------------------------

    for name, pattern in VERSION_PATTERNS:

        match = pattern.search(
            text
        )

        if match:

            product = name
            version = match.group(1)

            break

    # --------------------------------------------------------
    # Confidence
    # --------------------------------------------------------

    if product and version:

        confidence = "High"

    elif server:

        confidence = "Medium"

    else:

        confidence = "Low"

    return {

        "available": True,

        "raw": text,

        "server": server,

        "version": version,

        "product": product,

        "confidence": confidence
    }


# ============================================================
# SERVICE BANNER ANALYSIS
# ============================================================

def analyze_service_banner(
    service
):

    banner = service.get(
        "banner"
    )

    result = classify_banner(
        banner
    )

    return {

        "port": service.get(
            "port"
        ),

        "protocol": service.get(
            "protocol",
            "TCP"
        ),

        "service": service.get(
            "service",
            "Unknown"
        ),

        "state": service.get(
            "state",
            "unknown"
        ),

        "banner_available":
            result["available"],

        "banner":
            result["raw"],

        "server":
            result["server"],

        "product":
            result["product"],

        "version":
            result["version"],

        "confidence":
            result["confidence"]
    }


# ============================================================
# HOST BANNER ANALYSIS
# ============================================================

def analyze_host_banners(
    services
):

    results = []

    for service in services:

        if not isinstance(
            service,
            dict
        ):
            continue

        results.append(
            analyze_service_banner(
                service
            )
        )

    return results


# ============================================================
# BANNER SUMMARY
# ============================================================

def summarize_banners(
    banner_results
):

    total = len(
        banner_results
    )

    available = sum(
        1
        for item in banner_results
        if item.get(
            "banner_available"
        )
    )

    identified = sum(
        1
        for item in banner_results
        if item.get(
            "product"
        )
    )

    high_confidence = sum(
        1
        for item in banner_results
        if item.get(
            "confidence"
        ) == "High"
    )

    medium_confidence = sum(
        1
        for item in banner_results
        if item.get(
            "confidence"
        ) == "Medium"
    )

    return {

        "total_services":
            total,

        "banners_available":
            available,

        "products_identified":
            identified,

        "high_confidence":
            high_confidence,

        "medium_confidence":
            medium_confidence
    }


# ============================================================
# PRINT BANNER INTELLIGENCE
# ============================================================

def print_banner_intelligence(
    results
):

    print()
    print("=" * 72)
    print("BANNER INTELLIGENCE")
    print("=" * 72)

    if not results:

        print(
            "No service banners available."
        )

        return

    for item in results:

        print()

        print(
            f"Port      : "
            f"{item.get('port', 'Unknown')}"
        )

        print(
            f"Protocol  : "
            f"{item.get('protocol', 'TCP')}"
        )

        print(
            f"Service   : "
            f"{item.get('service', 'Unknown')}"
        )

        print(
            f"Available : "
            f"{item.get('banner_available', False)}"
        )

        print(
            f"Product   : "
            f"{item.get('product') or 'Unknown'}"
        )

        print(
            f"Version   : "
            f"{item.get('version') or 'Unknown'}"
        )

        print(
            f"Server    : "
            f"{item.get('server') or 'Unknown'}"
        )

        print(
            f"Confidence: "
            f"{item.get('confidence', 'Low')}"
        )