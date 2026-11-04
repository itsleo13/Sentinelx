from colorama import Fore, Style


def show_banner():

    cyan = Fore.CYAN + Style.BRIGHT
    green = Fore.GREEN + Style.BRIGHT
    yellow = Fore.YELLOW + Style.BRIGHT
    reset = Style.RESET_ALL

    print()

    print(
        cyan
        + r"""
███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     ██╗  ██╗
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ╚██╗██╔╝
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║      ╚███╔╝
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║      ██╔██╗
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗██╔╝ ██╗
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═╝
"""
        + reset
    )

    print(
        yellow
        + "                ◈ AI-POWERED SECURITY INTELLIGENCE ◈"
        + reset
    )

    print()

    print(
        cyan
        + "     ┌──────────────────────────────────────────────────────┐"
        + reset
    )

    print(
        cyan
        + "     │"
        + reset
        + "  SYSTEM STATUS      "
        + green
        + "● ONLINE"
        + reset
        + "                         "
        + cyan
        + "│"
        + reset
    )

    print(
        cyan
        + "     │"
        + reset
        + "  THREAT ENGINE      "
        + green
        + "● ACTIVE"
        + reset
        + "                         "
        + cyan
        + "│"
        + reset
    )

    print(
        cyan
        + "     │"
        + reset
        + "  ML ANALYZER        "
        + green
        + "● READY"
        + reset
        + "                          "
        + cyan
        + "│"
        + reset
    )

    print(
        cyan
        + "     │"
        + reset
        + "  CHANGE DETECTOR    "
        + green
        + "● MONITORING"
        + reset
        + "                     "
        + cyan
        + "│"
        + reset
    )

    print(
        cyan
        + "     └──────────────────────────────────────────────────────┘"
        + reset
    )

    print()

    print(
        Fore.YELLOW
        + Style.BRIGHT
        + "              [ SECURITY OPERATIONS COMMAND CENTER ]"
        + reset
    )

    print()