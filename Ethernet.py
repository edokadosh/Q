import struct
from LayerParser import LayerParser

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