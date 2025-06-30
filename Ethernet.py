import struct
from LayerParser import LayerParser
from enum import Enum
from utils import mac_to_bytes, bytes_to_mac, ip_to_bytes, bytes_to_ip


ETHERNET_HEADER_FORMAT = '!6s6sH'  # Destination MAC, Source MAC, EtherType
ETHERNET_BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'

class EthernetType(Enum):
    IPV4 = 0x0800
    ARP = 0x0806

EthernetTypeToNextLayerLength = {
    EthernetType.IPV4: 20,
    EthernetType.ARP: 28,
}

class Ethernet(LayerParser):
    def __init__(self, mac_address, ethertype=None):
        self.mac_address = mac_address.lower()
        self.ethertype = ethertype

    def recv(self, data):
        header_size = struct.calcsize(ETHERNET_HEADER_FORMAT)
        if len(data) < header_size:
            raise ValueError(f"Invalid Ethernet frame length {len(data)}, Expected: {struct.calcsize(ETHERNET_HEADER_FORMAT)}")

        dst_mac, src_mac, ethertype = struct.unpack(ETHERNET_HEADER_FORMAT, data[:14])
        dst_mac = bytes_to_mac(dst_mac)
        src_mac = bytes_to_mac(src_mac)
        
        if ethertype not in EthernetType._value2member_map_.keys():
            print(f"Unsupported Ethernet type: {ethertype}")
            return None, None

        payload_length = EthernetTypeToNextLayerLength.get(EthernetType(ethertype), 0)
        if len(data) < header_size + payload_length:
            raise ValueError(f"Invalid Ethernet frame length {len(data)}, Expected: {header_size + payload_length}")

        payload = data[header_size:]
        if self.ethertype and ethertype != self.ethertype.value:
            return None, None

        if dst_mac == self.mac_address or dst_mac == ETHERNET_BROADCAST_MAC:
            return {
                'dst_mac': dst_mac,
                'src_mac': src_mac,
                'ethertype': ethertype,
            }, payload
        
        return None, None
    
    def encapsulate(self, dst_mac, ethertype, payload):
        dst_mac_bytes = mac_to_bytes(dst_mac)
        src_mac_bytes = mac_to_bytes(self.mac_address)
        ethertype_bytes = struct.pack('!H', ethertype.value)
        return dst_mac_bytes + src_mac_bytes + ethertype_bytes + payload