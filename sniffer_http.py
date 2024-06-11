from scapy.all import *
import constants as c
import os

# Function to get the MAC address for a given IP
def get_mac(ip):
    responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, retry=10)
    for s, r in responses:
        return r[Ether].src
    return None


def content(pkt):
	if pkt.haslayer(TCP) and pkt.src in VICTIM_SERVER_MAC:
		if pkt[TCP].dport in HTTP_PORT:
			wrpcap("content.pcap",pkt,append=True)
def checkfile(filename):
	if os.path.exists(filename):
		clear = input("Do you want to reset the pcap (Y|N): \t")
		if clear.upper() == "Y":
			os.remove(filename)

def main():
	# filename = input("File name?\t")
	filename = "content.pcap"
	checkfile(filename)
	sniff(count=5,lfilter=content)

HTTP_PORT = [443,80]
VICTIM_SERVER_MAC = [get_mac(c.VICTIM_IP),get_mac(c.VICTIM_IP)]

if __name__ == "__main__":
	main()
