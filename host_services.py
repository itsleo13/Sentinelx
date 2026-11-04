import socket
import time


# ============================================================
# COMMON TCP SERVICES
# ============================================================

COMMON_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
}


# ============================================================
# TCP CONNECT
# ============================================================

def check_port(
    ip,
    port,
    timeout=0.5
):

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(
        timeout
    )

    start = time.time()

    try:

        result = sock.connect_ex(
            (ip, port)
        )

        elapsed = (
            time.time() - start
        )

        if result == 0:

            return {
                "port": port,
                "protocol": "TCP",
                "service":
                    COMMON_PORTS.get(
                        port,
                        "unknown"
                    ),
                "state": "open",
                "latency_ms":
                    round(
                        elapsed * 1000,
                        2
                    )
            }

        return None

    except OSError:

        return None

    finally:

        sock.close()


# ============================================================
# BANNER
# ============================================================

def get_banner(
    ip,
    port,
    timeout=1.0
):
    """Best-effort application/service fingerprinting."""

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(timeout)

    try:
        sock.connect((ip, port))

        # HTTP
        if port in (
            80,
            8000,
            8008,
            8080,
            8081,
            8888
        ):
            request = (
                "HEAD / HTTP/1.0\\r\\n"
                "Host: localhost\\r\\n"
                "Connection: close\\r\\n"
                "\\r\\n"
            )

            sock.sendall(
                request.encode()
            )

        # HTTPS/TLS needs a TLS handshake.
        elif port in (
            443,
            8443
        ):
            return None

        # DNS/TCP is a binary length-prefixed protocol,
        # so generic recv() must not be treated as a banner.
        elif port == 53:
            return None

        data = sock.recv(1024)

        if not data:
            return None

        # Avoid treating binary protocol data as text.
        if b"\\x00" in data[:64]:
            return None

        banner = data.decode(
            "utf-8",
            errors="replace"
        )

        banner = (
            banner
            .replace("\\r", " ")
            .replace("\\n", " ")
            .replace("\\t", " ")
            .strip()
        )

        if not banner:
            return None

        return banner[:300]

    except (
        OSError,
        socket.timeout
    ):
        return None

    finally:
        sock.close()


# ============================================================
# SERVICE ENUMERATION
# ============================================================

def enumerate_services(
    ip,
    ports=None,
    timeout=0.5,
    collect_banners=True
):

    if ports is None:

        ports = list(
            COMMON_PORTS.keys()
        )

    services = []

    for port in ports:

        result = check_port(
            ip,
            port,
            timeout
        )

        if not result:

            continue

        if collect_banners:

            result["banner"] = (
                get_banner(
                    ip,
                    port
                )
            )

        else:

            result["banner"] = None

        services.append(
            result
        )

    services.sort(
        key=lambda item:
            item["port"]
    )

    return services


# ============================================================
# HOST SERVICE PROFILE
# ============================================================

def build_service_profile(
    host,
    ports=None
):

    ip = host.get(
        "ip"
    )

    if not ip:

        return host

    services = enumerate_services(
        ip,
        ports=ports
    )

    host["services"] = services

    host["open_ports"] = [
        {
            "port":
                service["port"],

            "protocol":
                service["protocol"],

            "service":
                service["service"],

            "banner":
                service.get("banner")
        }

        for service in services
    ]

    host["open_port_count"] = len(
        services
    )

    return host


# ============================================================
# MULTI-HOST SERVICE PROFILING
# ============================================================

def profile_host_services(
    hosts,
    ports=None
):

    profiles = []

    for host in hosts:

        profile = dict(
            host
        )

        profile = build_service_profile(
            profile,
            ports=ports
        )

        profiles.append(
            profile
        )

    return profiles


# ============================================================
# SERVICE SUMMARY
# ============================================================

def summarize_services(
    hosts
):

    total_hosts = len(
        hosts
    )

    hosts_with_services = 0
    total_open_ports = 0

    service_counts = {}

    for host in hosts:

        services = host.get(
            "services",
            []
        )

        if services:

            hosts_with_services += 1

        total_open_ports += len(
            services
        )

        for service in services:

            name = service.get(
                "service",
                "unknown"
            )

            service_counts[name] = (
                service_counts.get(
                    name,
                    0
                ) + 1
            )

    return {

        "total_hosts":
            total_hosts,

        "hosts_with_services":
            hosts_with_services,

        "total_open_ports":
            total_open_ports,

        "service_counts":
            service_counts

    }


# ============================================================
# DISPLAY
# ============================================================

def print_service_profiles(
    hosts
):

    print()

    print("=" * 72)
    print("HOST SERVICE INTELLIGENCE")
    print("=" * 72)

    if not hosts:

        print(
            "No hosts available."
        )

        return

    for host in hosts:

        print()

        print(
            f"Host: "
            f"{host.get('ip', 'Unknown')}"
        )

        print(
            f"Device: "
            f"{host.get('hostname', 'Unknown')}"
        )

        services = host.get(
            "services",
            []
        )

        if not services:

            print(
                "  No common TCP "
                "services detected."
            )

            continue

        for service in services:

            print(
                f"  [OPEN] "
                f"{service['port']:<5} "
                f"{service['service']}"
            )

            print(
                f"         "
                f"Latency: "
                f"{service['latency_ms']} ms"
            )

            banner = service.get(
                "banner"
            )

            if banner:

                print(
                    f"         "
                    f"Banner: "
                    f"{banner[:150]}"
                )