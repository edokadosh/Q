from scapy.all import *
import threading
import socket



IN_IFACE = "enp0s8"
OUT_IFACE = "enp0s9"

IN_LEG_IP = "192.168.56.101"
OUT_LEG_IP = "192.168.106.3"

IN_LEG_MAC = "08:00:27:1f:0f:7b"
OUT_LEG_MAC = "08:00:27:03:33:bc"


def route(new_packet):
    new_packet[Ether].src = OUT_LEG_MAC
    new_packet[Ether].dst = "ff:ff:ff:ff:ff:ff"
    new_packet[IP].ttl = new_packet[IP].ttl - 1

    del new_packet[IP].chksum  # recalculate checksum
    return new_packet


def get_random_free_port(): # just for testing purposes, in real case nat coult manage its own ports
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((OUT_LEG_IP, 0))
        return s.getsockname()[1]


nat_table = {
    # outside_port : (in_ip, inside_port)
}

icmp_nat_table = {
    # icmp id : in_ip
}



def handle_nat_outwards(pkt):
    src_ip = pkt[IP].src
    pkt[IP].src = OUT_LEG_IP

    if TCP in pkt or UDP in pkt:
        src_port = pkt[TCP].sport if TCP in pkt else pkt[UDP].sport
        new_src_port = get_random_free_port()
        nat_table[new_src_port] = (src_ip, src_port)
    
        if TCP in pkt:
            pkt[TCP].sport = new_src_port
        elif UDP in pkt:
            pkt[UDP].sport = new_src_port
    elif ICMP in pkt:
        icmp_id = pkt[ICMP].id
        icmp_nat_table[icmp_id] = src_ip
    else:
        print("Unsupported packet type, dropping.")
        return

    sendp(route(pkt), iface=OUT_IFACE)
    print(f"Translated outwards {src_ip}:{src_port} to {OUT_LEG_IP}:{new_src_port}")

def handle_nat_inwards(pkt):
    if pkt[IP].dst == OUT_LEG_IP:
        if TCP in pkt or UDP in pkt:
            dst_port = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport
            if dst_port not in nat_table:
                print(f"Packet with unknown destination port {dst_port} received, dropping.")
                return
            
            in_ip, inside_port = nat_table[dst_port]
            pkt[IP].dst = in_ip
            if TCP in pkt:
                pkt[TCP].dport = inside_port
            elif UDP in pkt:
                pkt[UDP].dport = inside_port

        elif ICMP in pkt:
            icmp_id = pkt[ICMP].id
            if icmp_id not in icmp_nat_table:
                print(f"ICMP packet with unknown ID {icmp_id} received, dropping.")
                return
            
            in_ip = icmp_nat_table[icmp_id]
            pkt[IP].dst = in_ip
        else:
            print("Unsupported packet type, dropping.")
            return
        
        sendp(route(pkt), iface=IN_IFACE)
        print(f"Translate inwards {OUT_LEG_IP}:{dst_port} to {in_ip}:{inside_port}")
                
            

def nat_outwards():
    sniff(iface=IN_IFACE, prn=handle_nat_outwards, filter=f"ip and ether dst {IN_LEG_MAC}")

def nat_inwards():
    sniff(iface=OUT_IFACE, prn=handle_nat_inwards, filter=f"ip and dst host {OUT_LEG_IP}")

def main():
    t_outwards = threading.Thread(target=nat_outwards)
    t_inwards = threading.Thread(target=nat_inwards)
    t_outwards.start()
    t_inwards.start()



if __name__ == "__main__":
    main()