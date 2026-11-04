import socket
import ipaddress
import time
import concurrent.futures
import concurrent.futures

from scapy.all import ARP, Ether, srp


# ============================================================
# LOCAL NETWORK
# ============================================================

def get_local_ip():
    """
    Detect the IPv4 address selected by the OS
    for the active network route.

    No application data is sent.
    """

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    try:

        sock.connect(
            ("192.0.2.1", 80)
        )

        local_ip = sock.getsockname()[0]

        if (
            not local_ip
            or local_ip.startswith("127.")
        ):
            return None

        return local_ip

    except OSError:

        return None

    finally:

        sock.close()


def get_local_network():

    try:

        local_ip = get_local_ip()

        if not local_ip:

            return None

        network = ipaddress.ip_network(
            f"{local_ip}/24",
            strict=False
        )

        return str(network)

    except (
        OSError,
        ValueError
    ):

        return None


# ============================================================
# HOSTNAME
# ============================================================

def resolve_hostname(ip):

    try:

        hostname = socket.gethostbyaddr(
            ip
        )[0]

        return hostname

    except (
        socket.herror,
        socket.gaierror,
        OSError
    ):

        return "Unknown"


# ============================================================
# MAC NORMALIZATION
# ============================================================

def normalize_mac(mac):

    if not mac:

        return "Unknown"

    return mac.lower()


# ============================================================
# MAC VENDOR
# ============================================================

def get_vendor(mac):

    """
    Offline OUI/vendor lookup placeholder.

    A vendor database can be connected later
    without changing the discovery pipeline.
    """

    if not mac:

        return "Unknown"

    return "Unknown"


# ============================================================
# HOST PROFILE
# ============================================================

def build_host_profile(
    ip,
    mac
):

    mac = normalize_mac(
        mac
    )

    hostname = resolve_hostname(
        ip
    )

    vendor = get_vendor(
        mac
    )

    return {

        "ip":
            ip,

        "mac":
            mac,

        "hostname":
            hostname,

        "vendor":
            vendor,

        "status":
            "up"

    }


# ============================================================
# ARP DISCOVERY
# ============================================================

def discover_hosts(
    subnet,
    timeout=2
):

    hosts = []

    try:

        network = ipaddress.ip_network(
            subnet,
            strict=False
        )

    except ValueError:

        print(
            "Invalid subnet."
        )

        return hosts

    if network.version != 4:

        print(
            "ARP discovery currently "
            "supports IPv4 networks only."
        )

        return hosts

    start_time = time.time()

    # --------------------------------------------------------
    # PRIMARY METHOD: ARP DISCOVERY
    # --------------------------------------------------------

    try:

        arp_request = ARP(
            pdst=str(network)
        )

        ethernet = Ether(
            dst="ff:ff:ff:ff:ff:ff"
        )

        packet = (
            ethernet /
            arp_request
        )

        answered, unanswered = srp(
            packet,
            timeout=timeout,
            verbose=False
        )

        seen_ips = set()

        for sent, received in answered:

            ip = received.psrc

            mac = received.hwsrc

            if ip in seen_ips:

                continue

            seen_ips.add(
                ip
            )

            host = build_host_profile(
                ip,
                mac
            )

            host[
                "discovery_method"
            ] = "ARP"

            hosts.append(
                host
            )

        if hosts:

            elapsed = (
                time.time()
                - start_time
            )

            for host in hosts:

                host[
                    "discovery_time"
                ] = round(
                    elapsed,
                    3
                )

            hosts.sort(
                key=lambda host:
                ipaddress.ip_address(
                    host["ip"]
                )
            )

            return hosts

    except PermissionError:

        print(
            "ARP discovery unavailable. "
            "Using TCP fallback discovery..."
        )

    except Exception as error:

        print(
            "ARP discovery unavailable. "
            f"Using fallback discovery ({error})..."
        )

    # --------------------------------------------------------
    # FALLBACK METHOD: TCP CONNECT DISCOVERY
    # --------------------------------------------------------

    def probe_host(ip):

        common_ports = (
            53,
            80,
            443,
            22,
            445,
            3389
        )

        for port in common_ports:

            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )

            sock.settimeout(
                0.5
            )

            try:

                result = sock.connect_ex(
                    (
                        str(ip),
                        port
                    )
                )

                # ------------------------------------------------
                # A successful connection proves the host is alive.
                # Connection refused also indicates a reachable host
                # actively responded, even though the port is closed.
                # ------------------------------------------------

                if result in (
                    0,
                    111
                ):

                    return str(ip)

            except OSError:

                pass

            finally:

                sock.close()

        return None

    host_ips = list(
        network.hosts()
    )

    print(
        f"Testing up to {len(host_ips)} "
        "addresses with fallback discovery..."
    )

    discovered = []

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=64
    ) as executor:

        futures = {
            executor.submit(
                probe_host,
                ip
            ): ip
            for ip in host_ips
        }

        for future in concurrent.futures.as_completed(
            futures
        ):

            try:

                ip = future.result()

            except Exception:

                continue

            if ip:

                discovered.append(
                    ip
                )

    seen_ips = set()

    for ip in discovered:

        if ip in seen_ips:

            continue

        seen_ips.add(
            ip
        )

        host = build_host_profile(
            ip,
            None
        )

        host[
            "discovery_method"
        ] = "TCP_FALLBACK"

        hosts.append(
            host
        )

    elapsed = (
        time.time()
        - start_time
    )

    for host in hosts:

        host[
            "discovery_time"
        ] = round(
            elapsed,
            3
        )

    hosts.sort(
        key=lambda host:
        ipaddress.ip_address(
            host["ip"]
        )
    )

    return hosts



# ============================================================
# DISCOVERY SUMMARY
# ============================================================

def get_discovery_summary(
    hosts
):

    total_hosts = len(
        hosts
    )

    known_hostnames = sum(
        1
        for host in hosts
        if host.get(
            "hostname"
        ) != "Unknown"
    )

    known_vendors = sum(
        1
        for host in hosts
        if host.get(
            "vendor"
        ) != "Unknown"
    )

    return {

        "total_hosts":
            total_hosts,

        "known_hostnames":
            known_hostnames,

        "known_vendors":
            known_vendors,

        "unknown_hostnames":
            total_hosts
            - known_hostnames,

        "unknown_vendors":
            total_hosts
            - known_vendors

    }


# ============================================================
# DISCOVERY DETAILS
# ============================================================

def get_network_details():

    local_ip = get_local_ip()

    if not local_ip:

        return {

            "interface_ip":
                None,

            "network":
                None

        }

    try:

        network = ipaddress.ip_network(
            f"{local_ip}/24",
            strict=False
        )

    except ValueError:

        network = None

    return {

        "interface_ip":
            local_ip,

        "network":
            str(network)
            if network
            else None

    }