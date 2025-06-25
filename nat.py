from scapy.all import *
import threading
import socket

IN_IFACE = "enp0s8"
OUT_IFACE = "enp0s9"

IN_LEG_IP = "192.168.56.101"
OUT_LEG_IP = "192.168.106.3"

BAD_UDP_PORT = 12345

class BlockingRules:
    def __init__(
            self, 
            bad_src_port = [],
            bad_dst_port = [],
            bad_src_ip = [],
            bad_dst_ip = [],
            bad_src_mac = [],
            bad_dst_mac = []
        ):
        self.bad_src_port = bad_src_port
        self.bad_dst_port = bad_dst_port
        self.bad_src_ip = bad_src_ip 
        self.bad_dst_ip = bad_dst_ip
        self.bad_src_mac = bad_src_mac
        self.bad_dst_mac = bad_dst_mac
    
class firewall:
    def __init__(self, udp_rules: BlockingRules, tcp_rules: BlockingRules):
        self.udp_rules = udp_rules
        self.tcp_rules = tcp_rules

    def is_blocked(self, pkt):
        if UDP in pkt:
            if pkt[UDP].sport in self.udp_rules.bad_src_port or pkt[UDP].dport in self.udp_rules.bad_dst_port:
                return True
            if pkt[IP].src in self.udp_rules.bad_src_ip or pkt[IP].dst in self.udp_rules.bad_dst_ip:
                return True
            if pkt[Ether].src in self.udp_rules.bad_src_mac or pkt[Ether].dst in self.udp_rules.bad_dst_mac:
                return True
        elif TCP in pkt:
            if pkt[TCP].sport in self.tcp_rules.bad_src_port or pkt[TCP].dport in self.tcp_rules.bad_dst_port:
                return True
            if pkt[IP].src in self.tcp_rules.bad_src_ip or pkt[IP].dst in self.tcp_rules.bad_dst_ip:
                return True
            if pkt[Ether].src in self.tcp_rules.bad_src_mac or pkt[Ether].dst in self.tcp_rules.bad_dst_mac:
                return True
            
        return False

def get_random_free_port(): # just for testing purposes, in real case nat coult manage its own ports
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((OUT_LEG_IP, 0))
        return s.getsockname()[1]


nat_table = {
    # outside_port : (in_ip, inside_port)
}
IN_IP = 0
INSIDE_PORT = 1

def handle_nat_outwards(pkt):
    print(f"Received packet: {pkt.summary()}")
    if TCP not in pkt and UDP not in pkt:
        return
    src_port = pkt[TCP].sport if TCP in pkt else pkt[UDP].sport

    new_src_port = get_random_free_port()
    nat_table[new_src_port] = (pkt[IP].src, src_port)
    
    pkt[IP].src = OUT_LEG_IP
    if TCP in pkt:
        pkt[TCP].sport = new_src_port
    elif UDP in pkt:
        pkt[UDP].sport = new_src_port

    sendp(pkt, iface=OUT_IFACE)
    print(f"Translated outwards {nat_table[new_src_port][IN_IP]}:{src_port} to {OUT_LEG_IP}:{new_src_port}")



def handle_nat_inwards(pkt, rules: firewall):
    print(f"Received packet: {pkt.summary()}")
    if TCP not in pkt and UDP not in pkt:
        return
    dst_port = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport
    if rules.is_blocked(pkt):
        print(f"Packet blocked by firewall rules: {pkt.summary()}")
        return
    if pkt[IP].dst == OUT_LEG_IP:
        if dst_port not in nat_table:
            print(f"Packet with unknown destination port {dst_port} received, dropping.")
            return
        
        in_ip, inside_port = nat_table[dst_port]
        pkt[IP].dst = in_ip
        if TCP in pkt:
            pkt[TCP].dport = inside_port
        elif UDP in pkt:
            pkt[UDP].dport = inside_port

        sendp(pkt, iface=IN_IFACE)
        print(f"Translated inwards {OUT_LEG_IP}:{dst_port} to {in_ip}:{inside_port}")
                
            

def nat_outwards():
    sniff(iface=IN_IFACE, prn=handle_nat_outwards, filter=f"ip and dst host {IN_LEG_IP}")

def nat_inwards():
    rules = firewall(
        udp_rules=BlockingRules(
            bad_src_port=[BAD_UDP_PORT],
            bad_dst_port=[],
            bad_src_ip=["1.1.1.1"],
            bad_dst_ip=[],
            bad_src_mac=[],
            bad_dst_mac=[]
        ),
        tcp_rules=BlockingRules(
            bad_src_port=[BAD_UDP_PORT],
            bad_dst_port=[],
            bad_src_ip=[],
            bad_dst_ip=[],
            bad_src_mac=[],
            bad_dst_mac=[]
        )
    )
    sniff(iface=OUT_IFACE, prn=lambda p: handle_nat_inwards(p, rules), filter=f"ip and dst host {OUT_LEG_IP}")

def main():
    t_outwards = threading.Thread(target=nat_outwards)
    t_inwards = threading.Thread(target=nat_inwards)
    t_outwards.start()
    t_inwards.start()



if __name__ == "__main__":
    main()