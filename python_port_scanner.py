"""
This is an asynchronous port scanner, an upgraded version
of the synchronous port scanner that is faster by using
multithreading instead of checking ports one-by-one.

Author: Britton Janet

Updates: Creation 31MAY2025
"""


# imports the socket module used for network communication
import socket as sk
from concurrent.futures import ThreadPoolExecutor

TARGET_IP = "127.0.0.1"
START_PORT = 20
END_PORT = 8100		# these numbers are placeholders, scan any ports you may want.
MAX_THREADS = 100 		# you can tweak this, but don't go above 500... your machine could overload or get flagged on the network.

def scan_port(port):
    try:
        s = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
        s.settimeout(0.5)  # half-second timeout
        s.connect((TARGET_IP, port))
        print(f"[+] Port {port} is OPEN")
        s.close()
    except:
        pass

with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
    for port in range(START_PORT, END_PORT):
        executor.submit(scan_port, port)