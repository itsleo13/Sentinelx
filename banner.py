from colorama import Fore, Style, init

init(autoreset=True)

def show_banner():
    print(Fore.CYAN + "=" * 65)
    print(Fore.GREEN + Style.BRIGHT + "              SENTINELX")
    print(Fore.YELLOW + "      AI Powered Network Security Scanner")
    print(Fore.WHITE + "                Version 2.0")
    print(Fore.CYAN + "=" * 65)