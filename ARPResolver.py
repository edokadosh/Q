from scapy.all import conf
from ModularPacketParser import ModularPacketParser
from Ethernet import Ethernet, EthernetType
from ARP import ARP, ARPOperation


class ARPResolver():
    def __init__(self, interface):
        self.interface = interface
        self.my_mac = conf.ifaces[interface].mac
        self.my_ip = conf.ifaces[interface].ip

        self.raw_socket = conf.L2socket(iface=interface, promisc=True)

        self.parser = ModularPacketParser(parsers={
            'ethernet': Ethernet(self.my_mac, ethertype=EthernetType.ARP),
            'arp': ARP(),
        })

    def resolve(self, target_ip):
        arp_request = self.parser.encapsulate(
            ethernet={
                'dst_mac': 'ff:ff:ff:ff:ff:ff',
                'ethertype': EthernetType.ARP,
            },
            arp={
                'sender_hardware': self.my_mac,
                'sender_protocol': self.my_ip,
                'target_hardware': '00:00:00:00:00:00',
                'target_protocol': target_ip,
                'operation': ARPOperation.REQUEST
            }
        )

        
        # wait for arp reply
        while True:
            self.raw_socket.send(arp_request)
            parsed_response = self.parser.recv(self.raw_socket)
            if parsed_response and parsed_response['arp']['operation'] == ARPOperation.REPLY.value and parsed_response['arp']['sender_protocol'] == target_ip:
                return parsed_response['arp']['sender_hardware']