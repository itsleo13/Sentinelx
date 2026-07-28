import socket

def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except OSError:
        return "Unknown"