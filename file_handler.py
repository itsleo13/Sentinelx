def save_report(target, open_ports, time_taken):
    with open("results/scan_results.txt", "w") as file:
        file.write("========== SENTINELX REPORT ==========\n")
        file.write(f"Target: {target}\n")
        file.write(f"Open Ports: {len(open_ports)}\n")
        file.write(f"Time Taken: {time_taken:.2f} seconds\n\n")

        if open_ports:
            file.write("Open Ports List:\n")
            for port in open_ports:
                file.write(f"- Port {port}\n")
        else:
            file.write("No Open Ports Found.\n")