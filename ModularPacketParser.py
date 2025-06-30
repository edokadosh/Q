from LayerParser import LayerParser

ETHERNET_HEADER_SIZE = 14

class ModularPacketParser:
    def __init__(self, parsers: dict[str, LayerParser]):
        self.parsers = parsers
    

    def recv(self, raw_socket):
        while True:
            parsed_packet = {}
            next_layer_payload = raw_socket.recv_raw()[1]
            if not next_layer_payload:
                continue
            for parser_name, parser in self.parsers.items():
                parsed_layer, next_layer_payload = parser.recv(next_layer_payload)
                if not parsed_layer:
                    break
                # print(f"Parsed {parser_name}: {parsed_layer}")
                parsed_packet[parser_name] = parsed_layer
            
            if parsed_layer:
                return parsed_packet
            else:
                continue


    def encapsulate(self, **kwargs):
        encapsulated_data = None
        for parser_name, parser in reversed(self.parsers.items()):
            if parser_name in kwargs:
                encapsulated_data = parser.encapsulate(payload=encapsulated_data, **kwargs[parser_name])
        return encapsulated_data
    