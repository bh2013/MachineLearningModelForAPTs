#This file will act as a wireshark to run and read the data in real time 
import psutil
import pyshark
import scapy
import time
import os

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




def getInterfaces():
    # gets all interfaces and all info about them
    address = psutil.net_if_addrs()
    # returns just the names of interfaces 
    return address.keys()
    
    
    
    
    
    
def read_data():
    # Capture the packets
    interfaces = getInterfaces()
    print(interfaces)

    
    capture = pyshark.LiveCapture(interface="en0")
    
    
    packetList = []
    def print_callback(pkt):
        packetList.append(pkt)

        
    capture.apply_on_packets(print_callback, timeout=5, packet_count=5)
    
    print(packetList)   

        
        
    # capture = pyshark.LiveCapture(interface='en0')
    # capture.sniff(timeout=10)
    # for packet in capture.sniff_continuously(packet_count=5):
    #     print('Just arrived:', packet)
    #     packet.show()
    #     time.sleep(1)

# main function
if __name__ == "__main__":
    read_data()
    # scanPorts()