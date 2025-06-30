from abc import ABC, abstractmethod

class LayerParser(ABC):
    @abstractmethod
    def recv(self, data, raw_socket):
        pass

    @abstractmethod
    def encapsulate(self, payload, **kwargs):
        pass

class Plaintext(LayerParser):
    def __init__(self):
        pass

    def recv(self, data, raw_socket):
        return {
            'payload': data
        }, None

    def encapsulate(self, text):
        return text.encode('utf-8')