DEFAULT_TIMEOUT = 0.5
BANNER_TIMEOUT = 1.0
DEFAULT_WORKERS = 100


PROFILES = {
    "quick": {
        "start": 1,
        "end": 1024,
        "timeout": 0.3,
        "workers": 150,
        "banner": True,
        "description": "Fast scan of well-known ports."
    },

    "common": {
        "start": 1,
        "end": 10000,
        "timeout": 0.5,
        "workers": 100,
        "banner": True,
        "description": "Common TCP ports."
    },

    "full": {
        "start": 1,
        "end": 65535,
        "timeout": 0.5,
        "workers": 100,
        "banner": True,
        "description": "Full TCP port range."
    },

    "custom": {
        "start": None,
        "end": None,
        "timeout": 0.5,
        "workers": 100,
        "banner": True,
        "description": "User-defined port range."
    }
}


RISKY_SERVICES = {
    21: (
        "FTP",
        "Medium",
        "Prefer SFTP/FTPS and restrict exposure."
    ),

    23: (
        "Telnet",
        "High",
        "Replace Telnet with SSH."
    ),

    135: (
        "MS RPC",
        "Medium",
        "Restrict RPC exposure to trusted networks."
    ),

    139: (
        "NetBIOS",
        "Medium",
        "Restrict legacy file-sharing protocols."
    ),

    445: (
        "SMB",
        "Medium",
        "Restrict SMB and keep the host patched."
    ),

    3389: (
        "RDP",
        "High",
        "Restrict RDP and require strong authentication."
    ),

    5900: (
        "VNC",
        "High",
        "Restrict VNC and use secure remote access."
    )
}