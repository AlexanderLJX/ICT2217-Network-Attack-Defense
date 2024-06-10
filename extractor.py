import re
from scapy.all import rdpcap, TCP, Raw

def extract_credentials(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')
        username = re.findall(r'(uname|txtUsername|username|user|email)=([^&\s]+)', payload)
        password = re.findall(r'(pass|txtPassword|password|pwd)=([^&\s]+)', payload)
        if username or password:
            return (username, password)
    return None

def extract_credentials_from_pcap(pcap_file):
    packets = rdpcap(pcap_file)
    credentials = []
    for packet in packets:
        if packet.haslayer(TCP) and packet[TCP].dport == 80:  # HTTP typically runs over port 80
            creds = extract_credentials(packet)
            if creds:
                credentials.append(creds)
    return credentials

if __name__ == "__main__":
    pcap_file = 'content.pcap'  # Replace with your pcap file path

    credentials = extract_credentials_from_pcap(pcap_file)

    if credentials:
        print("[*] Credentials found:")
        for uname, pwd in credentials:
            print("Usernames: ", [u[1] for u in uname])
            print("Passwords: ", [p[1] for p in pwd])
    else:
        print("[*] No credentials found")