from scapy.all import conf
import struct
from abc import ABC, abstractmethod

class LayerParser(ABC):
    @abstractmethod
    def parse(self, data):
        pass

    @abstractmethod
    def encapsulate(self, payload, **kwargs):
        pass

class Plaintext(LayerParser):
    def __init__(self):
        pass

    def parse(self, data):
        return {
            'payload': data
        }

    def encapsulate(self, payload):
        return payload

ETHERNET_HEADER_FORMAT = '!6s6sH'  # Destination MAC, Source MAC, EtherType
ETHERTYPE_IPV4 = 0x0800

class Ethernet(LayerParser):
    def __init__(self, mac_address):
        self.mac_address = mac_address.lower()

    def parse(self, data):
        dst_mac, src_mac, ethertype = struct.unpack(ETHERNET_HEADER_FORMAT, data[:14])
        dst_mac = ':'.join(f'{b:02x}' for b in dst_mac).lower()
        src_mac = ':'.join(f'{b:02x}' for b in src_mac).lower()
        
        if dst_mac == self.mac_address:
            return {
                'dst_mac': dst_mac,
                'src_mac': src_mac,
                'ethertype': ethertype,
                'payload': data[14:]
            }
        return None
    
    def encapsulate(self, dst_mac, ethertype, payload):
        dst_mac_bytes = bytes.fromhex(dst_mac.replace(':', ''))
        src_mac_bytes = bytes.fromhex(self.mac_address.replace(':', ''))
        ethertype_bytes = struct.pack('!H', ethertype)
        return dst_mac_bytes + src_mac_bytes + ethertype_bytes + payload


class ModularPacketParser:
    def __init__(self, parsers: dict[str, LayerParser]):
        self.parsers = parsers
    
    def parse(self, data):
        parsed_packet = {}
        for parser_name, parser in self.parsers:
            parsed_layer = parser.parse(data)
            if not parsed_layer:
                return None
            if parsed_layer:
                parsed_packet[parser_name] = parsed_layer
        
        return parsed_packet

    def encapsulate(self, **kwargs):
        encapsulated_data = b''
        for parser_name, parser in reversed(self.parsers.items()):
            if parser_name in kwargs:
                encapsulated_data = parser.encapsulate(**kwargs[parser_name], payload=encapsulated_data)
        return encapsulated_data
    

MY_MAC_ADDRESS = "08:00:27:90:bc:1b"

def main():
    parser = ModularPacketParser(parsers={
        'ethernet': Ethernet(MY_MAC_ADDRESS),
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