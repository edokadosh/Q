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
        encapsulated_data = None
        for parser_name, parser in reversed(self.parsers.items()):
            if parser_name in kwargs:
                if encapsulated_data:
                    encapsulated_data = parser.encapsulate(payload=encapsulated_data, **kwargs[parser_name])
                else:
                    encapsulated_data = parser.encapsulate(**kwargs[parser_name])
        return encapsulated_data
    