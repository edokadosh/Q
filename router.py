from scapy.all import sniff, sendp

SRC_IFACE = "enp0s8"
DST_IFACE = "enp0s9"

def route(packet):
    sendp(packet, iface=DST_IFACE)
    print("sent packet")

def main():
    sniff(iface=SRC_IFACE, prn= route)

if __name__ == "__main__":
    main()