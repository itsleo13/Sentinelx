import socket
import time

from colorama import init
from banner import show_banner
from services import get_service_name
from file_handler import save_report

init(autoreset=True)

show_banner()

target = input("Enter Target IP or Domain: ").strip()

start_port = int(input("Enter Start Port: "))
end_port = int(input("Enter End Port: "))

print(f"\nScanning Target: {target}")
print("-" * 50)

start_time = time.time()

open_ports = []

try:
    target_ip = socket.gethostbyname(target)
    print(f"Resolved IP: {target_ip}\n")

    for port in range(start_port, end_port + 1):

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)

        result = sock.connect_ex((target_ip, port))

        if result == 0:
            service = get_service_name(port)

            print(f"[OPEN] Port {port:<5} Service: {service}")
            open_ports.append((port, service))

        sock.close()

except socket.gaierror:
    print("Error: Invalid Hostname or Domain.")

except KeyboardInterrupt:
    print("\nScan Interrupted by User.")

except Exception as e:
    print(f"Unexpected Error: {e}")

end_time = time.time()

print("\n" + "=" * 50)
print("Scan Completed")
print("=" * 50)

print(f"Target       : {target}")
print(f"Ports Scanned: {start_port} - {end_port}")
print(f"Open Ports   : {len(open_ports)}")
print(f"Time Taken   : {end_time - start_time:.2f} seconds")

if open_ports:
    print("\nOpen Port List:")
    for port, service in open_ports:
        print(f" - Port {port} ({service})")
else:
    print("\nNo Open Ports Found.")

save_report(target, open_ports, end_time - start_time)

print("\nReport saved to results/scan_results.txt")