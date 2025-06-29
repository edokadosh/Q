from abc import ABC, abstractmethod

class LayerParser(ABC):
    @abstractmethod
    def parse(self, data):
        pass

    @abstractmethod
    def encapsulate(self, payload, **kwargs):
        pass

class Plaintext(LayerParser):
    def __init__(self):
        pass

    def parse(self, data):
        return {
            'payload': data
        }

    def encapsulate(self, payload):
        return payload