import socket


COMMON_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "epmap",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    587: "smtp",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8000: "http-alt",
    8008: "http-alt",
    8080: "http-alt",
    8443: "https-alt",
    8888: "http-alt",
}


HTTP_PORTS = {
    80,
    8000,
    8008,
    8080,
    8443,
    8888,
}


def get_service_name(port):
    """
    Identify a service using:
    1. Known port mapping
    2. OS service database
    3. Generic protocol probing
    """

    # Known service mapping
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]

    # Operating system service database
    try:
        service = socket.getservbyport(
            port,
            "tcp"
        )

        if service:
            return service

    except OSError:
        pass

    # Unknown until banner/protocol detection
    return "Unknown"


def _receive_banner(sock):
    """
    Try to receive initial server response.
    """

    try:
        data = sock.recv(1024)

        if not data:
            return None

        return data.decode(
            "utf-8",
            errors="replace"
        ).strip()

    except (
        socket.timeout,
        ConnectionError,
        OSError
    ):
        return None


def _identify_from_banner(banner):
    """
    Try to identify service from returned banner.
    """

    if not banner:
        return None

    text = banner.lower()

    signatures = {
        "ssh": "ssh",
        "ftp": "ftp",
        "smtp": "smtp",
        "postfix": "smtp",
        "exim": "smtp",
        "imap": "imap",
        "pop3": "pop3",
        "mysql": "mysql",
        "mariadb": "mysql",
        "postgresql": "postgresql",
        "redis": "redis",
        "microsoft-ds": "smb",
        "samba": "smb",
        "telnet": "telnet",
        "vnc": "vnc",
    }

    for keyword, service in signatures.items():

        if keyword in text:
            return service

    # HTTP response detection
    if (
        "http/" in text
        or "server:" in text
        or "<html" in text
        or "<!doctype html" in text
    ):
        return "http"

    return None


def _http_probe(sock, target_ip):
    """
    Send a minimal HTTP request.
    """

    request = (
        f"HEAD / HTTP/1.0\r\n"
        f"Host: {target_ip}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    try:

        sock.sendall(request)

        data = sock.recv(1024)

        if not data:
            return None

        return data.decode(
            "utf-8",
            errors="replace"
        ).strip()

    except (
        socket.timeout,
        ConnectionError,
        OSError
    ):
        return None


def get_banner(target_ip, port):
    """
    Attempt to retrieve a service banner.

    For HTTP ports, send an HTTP request.
    For other TCP services, wait for a server banner.
    """

    try:

        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        ) as sock:

            sock.settimeout(2.0)

            result = sock.connect_ex(
                (target_ip, port)
            )

            if result != 0:
                return None

            # HTTP-specific probe
            if port in HTTP_PORTS:

                return _http_probe(
                    sock,
                    target_ip
                )

            # Generic banner grabbing
            return _receive_banner(sock)

    except (
        socket.timeout,
        ConnectionError,
        OSError
    ):
        return None


def detect_service(
    target_ip,
    port
):
    """
    Combined service detection.

    Returns:
        service_name, banner
    """

    service = get_service_name(
        port
    )

    banner = get_banner(
        target_ip,
        port
    )

    # If port mapping already identified service,
    # keep that known service.
    if service != "Unknown":
        return service, banner

    # Try identifying service from banner
    detected = _identify_from_banner(
        banner
    )

    if detected:
        service = detected

    return service, banner