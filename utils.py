
def mac_to_bytes(mac):
    try:
        return bytes.fromhex(mac.replace(':', '').replace('-', ''))
    except Exception as e:
        raise ValueError(f"Failed to convert MAC to bytes. Input: {mac}") from e

def bytes_to_mac(mac_bytes):
    try:
        return ':'.join(f'{b:02x}' for b in mac_bytes)
    except Exception as e:
        raise ValueError(f"Failed to convert bytes to MAC. Input: {mac_bytes}") from e

def ip_to_bytes(ip):
    try:
        return bytes(map(int, ip.split('.')))
    except Exception as e:
        raise ValueError(f"Failed to convert IP to bytes. Input: {ip}") from e

def bytes_to_ip(ip_bytes):
    try:
        return '.'.join(str(b) for b in ip_bytes)
    except Exception as e:
        raise ValueError(f"Failed to convert bytes to IP. Input: {ip_bytes}") from e


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