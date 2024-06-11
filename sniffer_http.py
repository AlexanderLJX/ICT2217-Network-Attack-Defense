from scapy.all import *
import constants as c
import os
HTTP_PORT = [443,80]
VICTIM_SERVER_MAC = [getmacbyip(c.VICTIM_IP),getmacbyip(c.VICTIM_IP)]

def content(pkt):
	if pkt.haslayer(TCP) and pkt.src in VICTIM_SERVER_MACfi:
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

if __name__ == "__main__":
	main()
