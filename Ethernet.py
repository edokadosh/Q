import struct
from LayerParser import LayerParser
from enum import Enum
from utils import mac_to_bytes, bytes_to_mac, ip_to_bytes, bytes_to_ip


ETHERNET_HEADER_FORMAT = '!6s6sH'  # Destination MAC, Source MAC, EtherType

class EthernetType(Enum):
    IPV4 = 0x0800
    ARP = 0x0806

EthernetTypeToNextLayerLength = {
    EthernetType.IPV4: 20,
    EthernetType.ARP: 28,
}

class Ethernet(LayerParser):
    def __init__(self, mac_address):
        self.mac_address = mac_address.lower()

    def recv(self, data, raw_socket):
        header_size = struct.calcsize(ETHERNET_HEADER_FORMAT)
        if len(data) < header_size:
            raise ValueError(f"Invalid Ethernet frame length {len(data)}, Expected: {struct.calcsize(ETHERNET_HEADER_FORMAT)}")

        dst_mac, src_mac, ethertype = struct.unpack(ETHERNET_HEADER_FORMAT, data[:14])
        dst_mac = bytes_to_mac(dst_mac)
        src_mac = bytes_to_mac(src_mac)
        
        if ethertype not in EthernetType._value2member_map_.keys():
            raise ValueError(f"Unsupported Ethernet type: {ethertype}")

        payload_length = EthernetTypeToNextLayerLength.get(EthernetType(ethertype), 0)
        if len(data) >= header_size + payload_length:
            payload = data[header_size:]
        else:
            payload = data[header_size:] + raw_socket.recv_raw(header_size + payload_length - len(data))[1]

        if dst_mac == self.mac_address or dst_mac == 'ff:ff:ff:ff:ff:ff':
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