from scapy.all import sniff
import constants as c


def packet_sniffer():
    sniff(filter="ip host " + c.VICTIM_IP, prn=lambda x: x.show())