from scapy.all import *
from ipaddress import ip_address, ip_network

IN_IFACE = "enp0s8"
OUT_IFACE = "enp0s9"

IN_LEG_IP = "192.168.56.101"
OUT_LEG_IP = "192.168.106.3"

IN_SUBNET = ip_network("192.168.56.0/24")
OUT_SUBNET = ip_network("192.168.106.0/24")


def route(packet):
    print("received packet")
    print(packet.summary())
    if IP in packet and ip_address(packet[IP].dst) in OUT_SUBNET:
        new_packet = packet.copy()
        new_packet[Ether].dst = "ff:ff:ff:ff:ff:ff"
        new_packet[IP].ttl = packet[IP].ttl - 1

        del new_packet[IP].chksum  # recalculate checksum
        sendp(new_packet, iface=OUT_IFACE)
        print("sent packet")

def main():
    sniff(iface=IN_IFACE, prn= route)

if __name__ == "__main__":
    main()

    