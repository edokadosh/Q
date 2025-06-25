from scapy.all import *

IN_IFACE = "enp0s8"
OUT_IFACE = "enp0s9"

IN_LEG_IP = "192.168.56.101"
OUT_LEG_IP = "192.168.106.3"

OUT_LEG_MAC = "08:00:27:03:33:bc"

def route(packet):
    print(f"Got packet from {packet[IP].src} to {packet[IP].dst}")
    new_packet = packet.copy()
    new_packet[IP].src = OUT_LEG_IP
    new_packet[Ether].src = OUT_LEG_MAC
    new_packet[Ether].dst = "ff:ff:ff:ff:ff:ff"
    new_packet[IP].ttl = packet[IP].ttl - 1

    del new_packet[IP].chksum  # recalculate checksum
    sendp(new_packet, iface=OUT_IFACE)

def main():
    sniff(iface=IN_IFACE, prn= route, filter=f"ip and dst host {IN_LEG_IP}")

if __name__ == "__main__":
    main()





