import re
from scapy.all import rdpcap, TCP, Raw

def extract_credentials(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')
        host = re.search(r'Host: (\S+)', payload)
        username = re.findall(r'(uname|txtUsername|username|user|email)=([^&\s]+)', payload)
        password = re.findall(r'(pass|txtPassword|password|pwd)=([^&\s]+)', payload)
        if host and (username or password):
            return (host.group(1), username, password)
    return None

def extract_credentials_from_pcap(pcap_file):
    packets = rdpcap(pcap_file)
    credentials = {}
    for packet in packets:
        if packet.haslayer(TCP) and packet[TCP].dport == 80:  # HTTP typically runs over port 80
            creds = extract_credentials(packet)
            if creds:
                host, usernames, passwords = creds
                uname = usernames[0][1] if usernames else 'N/A'
                pwd = passwords[0][1] if passwords else 'N/A'
                if host not in credentials:
                    credentials[host] = []
                credentials[host].append((uname, pwd))
    return credentials

if __name__ == "__main__":
    pcap_file = 'content.pcap'  # Replace with your pcap file path

    credentials = extract_credentials_from_pcap(pcap_file)

    if credentials:
        print("[*] Credentials found:")
        for host, creds in credentials.items():
            for uname, pwd in creds:
                print(f"{host}: Username: {uname}, Password: {pwd}")
    else:
        print("[*] No credentials found")
