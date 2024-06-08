from scapy.all import ARP, sniff, send
import os


def detect_arp_poison(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP response (is-at)
        try:
            # Get the real MAC address from the system ARP table
            real_mac = os.popen(f"arp -n {packet[ARP].psrc}").read().split()[3]
            response_mac = packet[ARP].hwsrc

            # Compare the real MAC address with the MAC address in the ARP response
            if real_mac != response_mac:
                print(
                    f"ARP Poisoning detected! Real MAC: {real_mac}, Fake MAC: {response_mac}"
                )
                # Optionally send corrective ARP response to fix the ARP table
                send(
                    ARP(
                        op=2,
                        psrc=packet[ARP].psrc,
                        pdst=packet[ARP].pdst,
                        hwsrc=real_mac,
                        hwdst="ff:ff:ff:ff:ff:ff",
                    ),
                    count=5,
                )
        except IndexError:
            pass


def main():
    print("Starting ARP poisoning detection")
    sniff(store=False, prn=detect_arp_poison)


if __name__ == "__main__":
    main()
