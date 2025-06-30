import struct
from LayerParser import LayerParser
from enum import Enum
from utils import IPV4_checksum

ICMP_HEADER_FORMAT = '!BBHI'

class ICMPType(Enum):
    ECHO_REPLY = 0
    ECHO_REQUEST = 8


class ICMP(LayerParser):
    def __init__(self):
        pass

    def recv(self, data):
        if len(data) < struct.calcsize(ICMP_HEADER_FORMAT):
            raise ValueError("Invalid ICMP packet length")
        
        icmp_type, code, checksum, rest_of_header = struct.unpack(ICMP_HEADER_FORMAT, data[:struct.calcsize(ICMP_HEADER_FORMAT)])
        if icmp_type not in ICMPType._value2member_map_.keys():
            raise ValueError(f"Unsupported ICMP type: {icmp_type}, possible values are {list(ICMPType._value2member_map_.keys())}")
        
        return {
            'type': icmp_type,
            'code': code,
            'checksum': checksum,
            'rest_of_header': rest_of_header
        }, data[struct.calcsize(ICMP_HEADER_FORMAT):]

    def encapsulate(self, icmp_type, code, rest_of_header, payload):
        if payload is None:
            payload = b''
        icmp_type = icmp_type.value
        checksum = 0
        header = struct.pack(ICMP_HEADER_FORMAT, icmp_type, code, checksum, rest_of_header)
        checksum = IPV4_checksum(header + payload)
        header = struct.pack(ICMP_HEADER_FORMAT, icmp_type, code, checksum, rest_of_header)
        return header + payload
        
