import struct
from LayerParser import LayerParser
from enum import Enum


ARP_HEADER_FORMAT = '!HHBBH'  # Hardware type, Protocol type, Hardware size, Protocol size, Operation

class HardwareType(Enum):
    ETHERNET = 1

class ProtocolType(Enum):
    IPV4 = 0x0800

HardwareSize = {
    HardwareType.ETHERNET: 6
}

ProtocolSize = {
    ProtocolType.IPV4: 4
}

class ARPOperation(Enum):
    REQUEST = 1
    REPLY = 2

class ARP(LayerParser):
    def __init__(self):
        pass

    def parse(self, data):
        arp_header_size = struct.calcsize(ARP_HEADER_FORMAT)
        if len(data) < arp_header_size:
            return None
        hardware_type, protocol_type, hardware_size, protocol_size, operation = struct.unpack(ARP_HEADER_FORMAT, data[:arp_header_size])
        
        sender_hardware, sender_protocol, target_hardware, target_protocol = struct.unpack(
            f'!{hardware_size}s{protocol_size}s{hardware_size}s{protocol_size}s',
            data[arp_header_size:arp_header_size + 2*hardware_size + 2*protocol_size]
        )

        if hardware_type == HardwareType.ETHERNET.value:
            sender_hardware = sender_hardware.hex().lower().replace(' ', ':')
            target_hardware = target_hardware.hex().lower().replace(' ', ':')
        
        if protocol_type == ProtocolType.IPV4.value:
            sender_protocol = '.'.join(str(b) for b in sender_protocol)
            target_protocol = '.'.join(str(b) for b in target_protocol)
    
        return {
            'hardware_type': hardware_type,
            'protocol_type': protocol_type,
            'hardware_size': hardware_size,
            'protocol_size': protocol_size,
            'operation': operation,
            'sender_hardware': sender_hardware.hex(),
            'sender_protocol': sender_protocol.hex(),
            'target_hardware': target_hardware.hex(),
            'target_protocol': target_protocol.hex()
        }

    def encapsulate(self, sender_hardware, sender_protocol, target_hardware, target_protocol, operation):
        hardware_type = HardwareType.ETHERNET.value
        protocol_type = ProtocolType.IPV4.value

        hardware_size = HardwareSize[HardwareType.ETHERNET]
        protocol_size = ProtocolSize[ProtocolType.IPV4]

        arp_header = struct.pack(
            ARP_HEADER_FORMAT,
            hardware_type,
            protocol_type,
            hardware_size,
            protocol_size,
            operation
        )                   

        sender_hardware_bytes = bytes.fromhex(sender_hardware.replace(':', ''))
        sender_protocol_bytes = bytes(map(int, sender_protocol.split('.')))
        target_hardware_bytes = bytes.fromhex(target_hardware.replace(':', ''))
        target_protocol_bytes = bytes(map(int, target_protocol.split('.')))
        arp_payload = struct.pack(
            f'!{hardware_size}s{protocol_size}s{hardware_size}s{protocol_size}s',
            sender_hardware_bytes,
            sender_protocol_bytes,
            target_hardware_bytes,
            target_protocol_bytes
        )

        return arp_header + arp_payload
