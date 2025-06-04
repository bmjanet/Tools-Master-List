"""
Asynchronous Multi-Target Port Scanner with Service Detection

This script scans one or more IP addresses or subnets for open ports using multithreading for speed.
It can detect basic services by port number and banner, and export results to JSON or CSV.
Supports scanning custom port lists/ranges and multiple hosts or subnets.

Author: Britton Janet
Updates: Creation 31MAY2025
"""


import socket as sk
from concurrent.futures import ThreadPoolExecutor
import argparse
import json
import csv
import ipaddress
import threading

# Common ports and services for detection, these traditionally cover many common services with vulnerabilities.
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP", 5900: "VNC"
}

def detect_service(port, banner):
    # Try to identify by banner, fallback to common ports
    for p, name in COMMON_PORTS.items():
        if port == p:
            return name
    if banner:
        banner = banner.lower()
        if b"http" in banner:
            return "HTTP"
        if b"ssh" in banner:
            return "SSH"
        if b"smtp" in banner:
            return "SMTP"
    return "Unknown"

def scan_port(ip, port, results, lock):
    try:
        with sk.socket(sk.AF_INET, sk.SOCK_STREAM) as s:
            s.settimeout(0.5)
            s.connect((ip, port))
            try:
                banner = s.recv(1024)
            except Exception:
                banner = b""
            service = detect_service(port, banner)
            with lock:
                results.append({"ip": ip, "port": port, "service": service, "banner": banner.decode(errors="ignore")})
    except (ConnectionRefusedError, sk.timeout, OSError):
        pass

# Function to parse ports from command line arguments, it can handle single ports, ranges, and comma-separated lists.
def parse_ports(args):
    if args.ports:
        ports = []
        for part in args.ports.split(","):
            if "-" in part:
                start, end = map(int, part.split("-"))
                ports.extend(range(start, end+1))
            else:
                ports.append(int(part))
        return sorted(set(ports))
    else:
        return list(range(args.start, args.end))

# Function to parse target IPs or subnets from command line arguments, it can handle single IPs, comma-separated lists, and subnets.
def parse_targets(args):
    targets = []
    if "/" in args.target:
        # Subnet
        net = ipaddress.ip_network(args.target, strict=False)
        targets = [str(ip) for ip in net.hosts()]
    else:
        # Comma-separated list
        targets = [t.strip() for t in args.target.split(",")]
    return targets

# Function to export results to JSON or CSV format, it will create a file with the results of the scan.
# Honestly, I don't use this function much, but it is useful for saving results and for displaying them in the GUI.
def export_results(results, args):
    if args.output:
        if args.output.endswith(".json"):
            with open(args.output, "w") as f:
                json.dump(results, f, indent=2)
        elif args.output.endswith(".csv"):
            with open(args.output, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=["ip", "port", "service", "banner"])
                writer.writeheader()
                writer.writerows(results)

# Main function to parse arguments and start scanning!!
def main():

    # Argument parser to handle command line arguments, it will take the target IPs, ports, threads, and output file.
    parser = argparse.ArgumentParser(description="Asynchronous Port Scanner")
    parser.add_argument("target", help="Target IP(s) or subnet (e.g. 192.168.1.1,192.168.1.2 or 192.168.1.0/24)")
    parser.add_argument("--start", type=int, default=1, help="Start port (if not using --ports)")
    parser.add_argument("--end", type=int, default=65535, help="End port (if not using --ports)")
    parser.add_argument("--ports", help="Comma-separated list of ports or ranges (e.g. 22,80,443,1000-1010)")
    # Default to 100 threads for scanning, be careful with this value, it can overload the target server! Less than 500 is a good idea.
    parser.add_argument("--threads", type=int, default=200, help="Max threads") 
    parser.add_argument("--output", help="Output file (.json or .csv)")
    args = parser.parse_args()

    results = []                    # List to store scan results
    lock = threading.Lock()         # Lock for thread-safe access to results
    ports = parse_ports(args)       # Parse ports from arguments, if not provided, use default range
    targets = parse_targets(args)   # Parse targets from arguments, if subnet is provided, expand it to individual IPs

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        for ip in targets:
            for port in ports:
                executor.submit(scan_port, ip, port, results, lock)
    executor.shutdown(wait=True)

    # Print summary
    for r in results:
        print(f"{r['ip']}:{r['port']} - {r['service']}")

    export_results(results, args)

if __name__ == "__main__":
    main()