import socket

def scanPorts():
    hostName = socket.gethostname()
    for port in range(65535):
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.bind((hostName, port))
        except:
            print("Port " + str(port) + " is open")
        
        server.close()