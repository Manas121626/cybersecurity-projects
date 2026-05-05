import socket
import datetime

# ============================================================
#   PORT SCANNER
#   Project by: [Your Name]
#   Concepts: Networking, TCP/IP, Open Ports, Security Auditing
# ============================================================

# Common ports and their services
COMMON_PORTS = {
    21:   "FTP (File Transfer Protocol)",
    22:   "SSH (Secure Shell)",
    23:   "Telnet",
    25:   "SMTP (Email Sending)",
    53:   "DNS (Domain Name System)",
    80:   "HTTP (Web Traffic)",
    110:  "POP3 (Email Receiving)",
    143:  "IMAP (Email Access)",
    443:  "HTTPS (Secure Web Traffic)",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop)",
    8080: "HTTP Alternate",
    8443: "HTTPS Alternate",
    5900: "VNC (Remote Access)",
    27017:"MongoDB Database",
}


def get_service(port):
    """Returns the known service name for a port."""
    return COMMON_PORTS.get(port, "Unknown Service")


def scan_port(host, port, timeout=1):
    """
    Tries to connect to a specific port on a host.
    Returns True if port is open, False if closed.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0  # 0 means connection successful = port is OPEN
    except socket.error:
        return False


def resolve_host(host):
    """Resolves hostname to IP address."""
    try:
        ip = socket.gethostbyname(host)
        return ip
    except socket.gaierror:
        return None


def scan_range(host, start_port, end_port):
    """Scans a range of ports on the given host."""
    open_ports = []
    total = end_port - start_port + 1

    print(f"\n  Scanning ports {start_port} to {end_port}...")
    print(f"  {'PORT':<8} {'STATUS':<10} {'SERVICE'}")
    print("  " + "-" * 45)

    for i, port in enumerate(range(start_port, end_port + 1)):
        # Show progress every 10 ports
        if total > 20 and i % 10 == 0:
            print(f"  ⏳ Progress: {i}/{total} ports scanned...", end="\r")

        is_open = scan_port(host, port)
        if is_open:
            service = get_service(port)
            print(f"  {port:<8} {'✅ OPEN':<10} {service}")
            open_ports.append((port, service))

    return open_ports


def scan_common_ports(host):
    """Scans only well-known common ports."""
    open_ports = []

    print(f"\n  Scanning {len(COMMON_PORTS)} common ports...")
    print(f"  {'PORT':<8} {'STATUS':<10} {'SERVICE'}")
    print("  " + "-" * 45)

    for port, service in COMMON_PORTS.items():
        is_open = scan_port(host, port)
        status = "✅ OPEN" if is_open else "🔴 CLOSED"
        print(f"  {port:<8} {status:<10} {service}")
        if is_open:
            open_ports.append((port, service))

    return open_ports


def display_summary(host, ip, open_ports, start_time, end_time):
    """Displays a summary of scan results."""
    duration = (end_time - start_time).total_seconds()

    print("\n" + "=" * 50)
    print("  📊 SCAN SUMMARY")
    print("=" * 50)
    print(f"  Host     : {host}")
    print(f"  IP       : {ip}")
    print(f"  Time     : {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Duration : {duration:.2f} seconds")
    print(f"  Open Ports Found : {len(open_ports)}")

    if open_ports:
        print("\n  ⚠️  OPEN PORTS (Potential Security Risks):")
        for port, service in open_ports:
            print(f"    → Port {port} : {service}")
        print("\n  💡 TIP: Open ports can be entry points for attackers.")
        print("     Close unused ports to improve security.")
    else:
        print("\n  ✅ No open ports found in scanned range.")
    print("=" * 50)


def main():
    print("=" * 50)
    print("   🔍 PORT SCANNER - Network Security Tool")
    print("=" * 50)
    print("  ⚠️  NOTE: Only scan systems you own or have")
    print("      permission to scan. Unauthorized scanning")
    print("      is illegal.")
    print("=" * 50)

    while True:
        print("\nWhat would you like to do?")
        print("  1. Scan common ports (quick scan)")
        print("  2. Scan a custom port range")
        print("  3. Scan a single port")
        print("  4. Exit")

        choice = input("\nEnter your choice (1/2/3/4): ").strip()

        if choice in ["1", "2", "3"]:
            host = input("\nEnter target IP or hostname (e.g. 127.0.0.1 or localhost): ").strip()

            # Resolve hostname to IP
            ip = resolve_host(host)
            if not ip:
                print(f"  ❌ Could not resolve host: {host}. Please check and try again.")
                continue

            print(f"\n  ✅ Host resolved: {host} → {ip}")
            start_time = datetime.datetime.now()

            # ---- Option 1: Common Ports ----
            if choice == "1":
                open_ports = scan_common_ports(ip)

            # ---- Option 2: Custom Range ----
            elif choice == "2":
                try:
                    start_port = int(input("  Enter start port (e.g. 1): "))
                    end_port   = int(input("  Enter end port (e.g. 1024): "))
                    if start_port < 1 or end_port > 65535 or start_port > end_port:
                        print("  ❌ Invalid port range. Ports must be between 1-65535.")
                        continue
                    if end_port - start_port > 500:
                        print(f"  ⚠️  Scanning {end_port - start_port + 1} ports may take a while...")
                    open_ports = scan_range(ip, start_port, end_port)
                except ValueError:
                    print("  ❌ Invalid input. Please enter numbers only.")
                    continue

            # ---- Option 3: Single Port ----
            elif choice == "3":
                try:
                    port = int(input("  Enter port number to scan: "))
                    if port < 1 or port > 65535:
                        print("  ❌ Port must be between 1 and 65535.")
                        continue
                    is_open = scan_port(ip, port)
                    service = get_service(port)
                    status  = "✅ OPEN" if is_open else "🔴 CLOSED"
                    print(f"\n  Port {port} ({service}) is {status}")
                    open_ports = [(port, service)] if is_open else []
                except ValueError:
                    print("  ❌ Invalid input. Please enter a number.")
                    continue

            end_time = datetime.datetime.now()
            display_summary(host, ip, open_ports, start_time, end_time)

        elif choice == "4":
            print("\n👋 Goodbye! Stay secure.\n")
            break

        else:
            print("  ⚠️  Invalid choice. Please enter 1, 2, 3 or 4.")


if __name__ == "__main__":
    main()