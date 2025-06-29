from LayerParser import LayerParser

class ModularPacketParser:
    def __init__(self, parsers: dict[str, LayerParser]):
        self.parsers = parsers
    
    def parse(self, data):
        parsed_packet = {}
        for parser_name, parser in self.parsers:
            parsed_layer = parser.parse(data)
            if not parsed_layer:
                return None
            if parsed_layer:
                parsed_packet[parser_name] = parsed_layer
        
        return parsed_packet

    def encapsulate(self, **kwargs):
        encapsulated_data = b''
        for parser_name, parser in reversed(self.parsers.items()):
            if parser_name in kwargs:
                encapsulated_data = parser.encapsulate(**kwargs[parser_name], payload=encapsulated_data)
        return encapsulated_data
    