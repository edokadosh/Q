import socket

UDP_IP = "127.0.0.1"
UDP_PORT = 12345
MESSAGE = b"hello"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for i in range(1000):
    sock.sendto(MESSAGE, (UDP_IP, UDP_PORT))
sock.close()