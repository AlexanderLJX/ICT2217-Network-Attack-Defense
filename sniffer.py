from scapy.all import sniff


def packet_sniffer():
    sniff(filter="ip host " + victim_ip, prn=lambda x: x.show())