import struct
from LayerParser import LayerParser
from enum import Enum
from utils import IPV4_checksum, mac_to_bytes, bytes_to_mac, ip_to_bytes, bytes_to_ip

VERSION = 4

IP_HEADER_FORMAT = '!BBHHHBBH4s4s'

class TransportLayerProtocol(Enum):
    ICMP = 1
    TCP = 6
    UDP = 17


class IP(LayerParser):
    def __init__(self):
        pass

    def recv(self, data):
        header_length = struct.calcsize(IP_HEADER_FORMAT)
        if len(data) < header_length:
            raise ValueError("Invalid IP packet length")

        header = struct.unpack(IP_HEADER_FORMAT, data[:header_length])

        version = header[0] >> 4
        ihl = header[0] & 0x0F
        
        if version != VERSION:
            return None, None
        
        total_length = header[2]
        ttl = header[5]
        protocol = header[6]
        if protocol not in [p.value for p in TransportLayerProtocol]:
            raise ValueError(f"Unsupported protocol: {protocol}")
        
        if len(data) < total_length:
            raise ValueError(f"Invalid IP packet length {len(data)}, Expected: {total_length}")

        payload = data[header_length:]

        calculated_checksum = IPV4_checksum(data[:total_length])
        if calculated_checksum != 0:
            return None, None

        src_ip = struct.unpack('!4B', header[8])
        dst_ip = struct.unpack('!4B', header[9])
        
        return {
            'version': version,
            'ihl': ihl,
            'total_length': total_length,
            'ttl': ttl,
            'protocol': protocol,
            'src_ip': bytes_to_ip(src_ip),
            'dst_ip': bytes_to_ip(dst_ip),
            'payload': data[struct.calcsize(IP_HEADER_FORMAT):]
        }, payload

    def encapsulate(self, src_ip, dst_ip, protocol, payload, ttl=64):
        version_ihl = (VERSION << 4) | 5 # ihl is the size of the header in 32-bit words - 5 means 20 bytes header without options
        total_length = 20 + len(payload)
        checksum = 0 

        src_ip = ip_to_bytes(src_ip)
        dst_ip = ip_to_bytes(dst_ip)
        protocol_value = protocol.value

        header_fields = [
            version_ihl,
            0,  # Type of Service
            total_length,
            0,  # Identification
            0,  # Flags and Fragment Offset
            ttl,
            protocol_value,
            checksum,  # Placeholder for checksum
            src_ip,
            dst_ip
        ]

        header = struct.pack(IP_HEADER_FORMAT, *header_fields)
        checksum = IPV4_checksum(header + payload)
        header_fields[7] = checksum
        header = struct.pack(IP_HEADER_FORMAT, *header_fields)

        checksum = IPV4_checksum(header + payload)

        return header + payload

        
