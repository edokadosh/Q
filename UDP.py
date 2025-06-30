import struct
from LayerParser import LayerParser
from enum import Enum
from utils import IPV4_checksum

UDP_HEADER_FORMAT = '!HHHH'


class UDP(LayerParser):
    def __init__(self, port):
        self.port = port

    def recv(self, data):
        header_length = struct.calcsize(UDP_HEADER_FORMAT)
        if len(data) < header_length:
            raise ValueError("Invalid UDP packet length")
        
        src_port, dst_port, length, checksum = struct.unpack(UDP_HEADER_FORMAT, data[:struct.calcsize(UDP_HEADER_FORMAT)])
        
        if length != len(data):
            raise ValueError("Invalid UDP packet length field")

        if dst_port == self.port:
            return {
                'src_port': src_port,
                'dst_port': dst_port,
                'length': length,
                'checksum': checksum
            }, data[struct.calcsize(UDP_HEADER_FORMAT):]
        else:
            return None, None
        

    def encapsulate(self, dst_port, payload=None):
        if payload is None:
            payload = b''
        src_port = self.port

        length = struct.calcsize(UDP_HEADER_FORMAT) + len(payload)
        checksum = 0
        header = struct.pack(UDP_HEADER_FORMAT, src_port, dst_port, length, checksum)
        
        return header + payload
        
