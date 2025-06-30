from scapy.all import conf
from ModularPacketParser import ModularPacketParser
from Ethernet import Ethernet, EthernetType
from ARP import ARP, ARPOperation
from LayerParser import Plaintext

# MY_MAC_ADDRESS = "08:00:27:90:bc:1b"

def get_interface_info():
    for index, i in enumerate(list(conf.ifaces.values())):
        if i.mac:
            print(f"{index}. Interface: {i.name}, MAC: {i.mac}")

    interface = None
    my_mac = None
    my_ip = None

    while not my_mac:
        interface_index = input("Enter the interface index: ")
        if interface_index.isdigit():
            interface_index = int(interface_index)
        else:
            print("Invalid input. Please enter a valid interface index.")
            continue
        if 0 <= interface_index < len(list(conf.ifaces.values())):
            interface = list(conf.ifaces.keys())[interface_index]
            my_mac = conf.ifaces[interface].mac
            my_ip = conf.ifaces[interface].ip
            print(f"Selected interface: {conf.ifaces[interface].name}")
            print(f"Using MAC address: {my_mac}")
            print(f"Using IP address: {my_ip}")
        else:
            print("Invalid interface. Please try again.")
            
    return interface, my_mac, my_ip

def main():
    interface, my_mac, my_ip = get_interface_info()

    parser = ModularPacketParser(parsers={
        'ethernet': Ethernet(my_mac),
        'arp': ARP(),
    })

    packet = parser.encapsulate(
        ethernet={
            'dst_mac': 'ff:ff:ff:ff:ff:ff',
            'ethertype': EthernetType.ARP.value,
        },
        arp={
            'sender_hardware': my_mac,
            'sender_protocol': my_ip,
            'target_hardware': 'ff:ff:ff:ff:ff:ff',
            'target_protocol': '1.1.1.1',
            'operation': ARPOperation.REQUEST.value
        }
    )

    iface = interface
    sock = conf.L2socket(iface=iface, promisc=True)
    sock.send(packet) # Send data
    recv = sock.recv_raw() # Receive data

if __name__ == "__main__":
    main()