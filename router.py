from scapy.all import *

SRC_IFACE = "enp0s8"
DST_IFACE = "enp0s9"

SRC_LEG_IP = "192.168.56.101"
DST_LEG_IP = "192.168.106.3"

def route(packet):
    print(f"Got packet from {packet[IP].src} to {packet[IP].dst}")
    packet[IP].src = DST_LEG_IP
    sendp(packet, iface=DST_IFACE)

def main():
    sniff(iface=SRC_IFACE, prn= route, filter=f"ip and dst host {SRC_LEG_IP}")

if __name__ == "__main__":
    main()