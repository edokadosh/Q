from scapy.all import conf
from ModularPacketParser import ModularPacketParser
from Ethernet import Ethernet, EthernetType
from ARP import ARP, ARPOperation
from IP import IP, TransportLayerProtocol
from ICMP import ICMP, ICMPType
from UDP import UDP
from SocketInterface import SocketInterface
from LayerParser import Plaintext
from ipaddress import ip_address, ip_network
import math
from ARPResolver import ARPResolver

def route_reverse_lookup(iface):
    return list(filter(lambda a: a[3] == iface , conf.route.__dict__["routes"]))[0]

class UDPSocket():
    def __init__(self, my_port, host, host_port):
        self.my_port = my_port
        self.host = host
        self.host_port = host_port

        iface, output_ip, gateway_ip = conf.route.route(host)
        net_mask = int(math.log2(2**32-route_reverse_lookup(iface)[1]))
        print(f"Using interface: {iface}, output IP: {output_ip}, gateway IP: {gateway_ip}, net mask: {net_mask}")
        self.iface = iface
        self.output_ip = output_ip
        self.gateway_ip = gateway_ip
        self.net_mask = net_mask

        self.my_mac = conf.ifaces[iface].mac
        self.my_ip = conf.ifaces[iface].ip

        self.raw_socket = conf.L2socket(iface=iface, promisc=True)

        self.parser = ModularPacketParser(parsers={
            'ethernet': Ethernet(self.my_mac),
            'ip': IP(),
            'udp': UDP(self.my_port), 
            'message': Plaintext(),
        })

        self.arp_resolver = ARPResolver(iface)

    def send(self, payload: bytes):
        if ip_address(self.host) in ip_network(f"{self.output_ip}/{self.net_mask}"):
            arp_target = self.host
        else:
            arp_target = self.gateway_ip

        dst_mac = self.arp_resolver.resolve(arp_target)

        packet = self.parser.encapsulate(
            ethernet={
                'dst_mac': dst_mac,
                'ethertype': EthernetType.IPV4,
            },
            ip={
                'src_ip': self.my_ip,
                'dst_ip': self.host,
                'protocol': TransportLayerProtocol.UDP,
            },
            udp={
                'dst_port': self.host_port,
            },
            message={
                'bytes': payload,
            }
        )
        self.raw_socket.send(packet)

    def recv(self):
        try:
            parsed, payload = self.parser.recv(self.raw_socket)
        except ValueError as e:
            print(f"Error parsing packet: {e}")
            return None
        
        return payload


    
