from LayerParser import LayerParser

ETHERNET_HEADER_SIZE = 14

class ModularPacketParser:
    def __init__(self, parsers: dict[str, LayerParser]):
        self.parsers = parsers
    

    def recv(self, raw_socket):
        parsed_packet = {}
        next_layer_payload = raw_socket.recv_raw(ETHERNET_HEADER_SIZE)[1]
        for parser_name, parser in self.parsers.items():
            parsed_layer, next_layer_payload = parser.recv(next_layer_payload, raw_socket)
            if not parsed_layer:
                raise ValueError(f"Failed to parse layer: {parser_name}")
            parsed_packet[parser_name] = parsed_layer
        
        return parsed_packet


    def encapsulate(self, **kwargs):
        encapsulated_data = None
        for parser_name, parser in reversed(self.parsers.items()):
            if parser_name in kwargs:
                encapsulated_data = parser.encapsulate(payload=encapsulated_data, **kwargs[parser_name])
        return encapsulated_data
    