from scapy.all import conf
from ModularPacketParser import ModularPacketParser
from Ethernet import Ethernet, ETHERTYPE_IPV4
from ARP import ARP
from LayerParser import Plaintext

# MY_MAC_ADDRESS = "08:00:27:90:bc:1b"

def main():
    for index, i in enumerate(list(conf.ifaces.values())):
        if i.mac:
            print(f"{index}. Interface: {i.name}, MAC: {i.mac}")
    
    interface = None
    my_mac = None

    while not my_mac:
        interface = input("Enter the interface index:")
        if interface.isdigit():
            interface = int(interface)
        else:
            print("Invalid input. Please enter a valid interface index.")
            continue
        if 0 <= interface < len(list(conf.ifaces.values())):
            my_mac = list(conf.ifaces.values())[interface].mac
            print(f"Selected interface: {list(conf.ifaces.values())[interface].name}")
            print(f"Using MAC address: {my_mac}")
        else:
            print("Invalid interface. Please try again.")

    parser = ModularPacketParser(parsers={
        'ethernet': Ethernet(my_mac),
        'plaintext': Plaintext()
    })

    packet = parser.encapsulate(
        ethernet={
            'dst_mac': 'ff:ff:ff:ff:ff:ff',
            'ethertype': ETHERTYPE_IPV4,
        },
        plaintext={
            'payload': b'Hello, World!'
        }
    )

    iface = "enp0s3"
    sock = conf.L2socket(iface=iface, promisc=True)
    sock.send(packet) # Send data
    recv = sock.recv_raw() # Receive data

if __name__ == "__main__":
    main()