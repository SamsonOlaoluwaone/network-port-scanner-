import socket
import time
import ipaddress
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

def detect_service(sock, target, port):
    http_ports = {80, 8000, 8080, 8081, 8888}

    if port in http_ports:
        try:
            request = (
                b"HEAD / HTTP/1.0\r\n"
                b"Host: " + target.encode() + b"\r\n\r\n"
            )
            sock.sendall(request)

            response = sock.recv(1024).decode(errors="ignore")
            lines = response.splitlines()

            status_line = lines[0] if lines else ""
            server_header = ""

            for line in lines:
                if line.lower().startswith("server:"):
                    server_header = line
                    break

            if server_header:
                return f"{server_header} → {status_line}"

            return status_line

        except (socket.timeout, socket.error):
            return ""

    try:
        banner = sock.recv(1024).decode(errors="ignore").strip()
        return banner

    except (socket.timeout, socket.error):
        return ""



def scan_port(target, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((target, port))

        if result == 0:
            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = "unknown"

            banner = detect_service(sock, target, port)

            return (port, service, banner)

        return None

    except socket.error:
        return None

    finally:
        sock.close()

def save_report(filename, target, start_port, end_port, timeout,
                open_ports, service_counts, total_ports,
                open_percentage, scan_duration):

    with open(filename, "w") as report:
        report.write("Network Port Scanner Report\n")
        report.write("=" * 40 + "\n\n")

        report.write(f"Target: {target}\n")
        report.write(f"Port range: {start_port}-{end_port}\n")
        report.write(f"Timeout: {timeout} seconds\n\n")

        report.write("Open Ports\n")
        report.write("-" * 40 + "\n")

        if open_ports:
            for port, service, banner in open_ports:
                if banner:
                    report.write(
                        f"Port {port} → OPEN → {service} → {banner}\n"
                    )
                else:
                    report.write(
                        f"Port {port} → OPEN → {service}\n"
                    )
        else:
            report.write("No open ports found.\n")

        if open_ports:
            report.write("\nService Summary\n")
            report.write("-" * 40 + "\n")

            for service, count in sorted(service_counts.items()):
                report.write(f"{service} → {count} port(s)\n")

        report.write("\nStatistics\n")
        report.write("-" * 40 + "\n")
        report.write(f"Total ports scanned: {total_ports}\n")
        report.write(f"Open ports found: {len(open_ports)}\n")
        report.write(f"Open port percentage: {open_percentage:.2f}%\n")
        report.write(f"Scan duration: {scan_duration:.2f} seconds\n")

def main():
    parser = argparse.ArgumentParser(
        description="Concurrent TCP network port scanner"
    )

    parser.add_argument(
        "target",
        help="Target IP address"
    )

    parser.add_argument(
        "start_port",
        type=int,
        help="Starting port"
    )

    parser.add_argument(
        "end_port",
        type=int,
        help="Ending port"
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1.0)"
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Save scan results to a text file"
    )

    args = parser.parse_args()

    target = args.target
    start_port = args.start_port
    end_port = args.end_port
    timeout = args.timeout
    output_file = args.output

    try:
        ipaddress.ip_address(target)
    except ValueError:
        print("Error: Invalid IP address.")
        return

    if timeout <= 0:
        print("Error: Timeout must be greater than 0.")
        return

    if start_port < 1 or end_port > 65535:
        print("Error: Ports must be between 1 and 65535.")
        return

    if start_port > end_port:
        print("Error: Starting port must be less than or equal to ending port.")
        return

    start_time = time.time()

    print(f"\nScanning {target}...")
    print("-" * 40)

    open_ports = []

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = []

        for port in range(start_port, end_port + 1):
            future = executor.submit(scan_port, target, port, timeout)
            futures.append(future)

        for future in as_completed(futures):
            try:
                result = future.result()

                if result is not None:
                    open_ports.append(result)

            except Exception as error:
                print(f"Warning: A scan task failed: {error}")

    end_time = time.time()
    scan_duration = end_time - start_time

    total_ports = end_port - start_port + 1
    open_percentage = (len(open_ports) / total_ports) * 100

    open_ports.sort()

    for port, service, banner in open_ports:
        if banner:
            print(f"Port {port} → OPEN → {service} → {banner}")
        else:
            print(f"Port {port} → OPEN → {service}")

    service_counts = {}

    for port, service, banner in open_ports:
        if service not in service_counts:
            service_counts[service] = 0

        service_counts[service] += 1

    if not open_ports:
        print("No open ports found.")
    else:
        print("\nService Summary")
        print("-" * 40)

        for service, count in sorted(service_counts.items()):
            print(f"{service} → {count} port(s)")

    print("-" * 40)
    print(f"Total ports scanned: {total_ports}")
    print(f"Open ports found: {len(open_ports)}")
    print(f"Open port percentage: {open_percentage:.2f}%")
    print(f"Scan duration: {scan_duration:.2f} seconds")

    if output_file:
        save_report(
            output_file,
            target,
            start_port,
            end_port,
            timeout,
            open_ports,
            service_counts,
            total_ports,
            open_percentage,
            scan_duration
        )

        print(f"Report saved to: {output_file}")

    print("Scan complete.")


if __name__ == "__main__":
    main()
