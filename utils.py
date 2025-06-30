

def mac_to_bytes(mac):
    return bytes.fromhex(mac.replace(':', '').replace('-', ''))

def bytes_to_mac(mac_bytes):
    return ':'.join(f'{b:02x}' for b in mac_bytes)

def ip_to_bytes(ip):
    return bytes(map(int, ip.split('.')))

def bytes_to_ip(ip_bytes):
    return '.'.join(str(b) for b in ip_bytes)


def IPV4_checksum(data):
    if len(data) % 2 != 0:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s += w
        s = (s >> 16) + (s & 0xFFFF)
    s = ~s & 0xFFFF
    return s