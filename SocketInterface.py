from abc import ABC, abstractmethod

class SocketInterface(ABC):
    @abstractmethod
    def __init__(self, src_port, host, dst_port):
        """
        This assumes there is a dst port, which is not always the case with UDP but for common usecases it is.
        """
        pass

    @abstractmethod
    def send(self, payload: bytes):
        pass

    @abstractmethod
    def recv(self):
        pass
