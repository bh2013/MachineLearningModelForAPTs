#This file will act as a wireshark to run and read the data in real time 

# Libriaries 
import psutil
import pyshark
import collections
import logging
# ---------------------z
# files to import 
import getPacketInfo
import ScanPorts
import UnitTest
import FormatDataPackets
# ---------------------

def getInterfaces():
    try:
        address = psutil.net_if_addrs()
        return address.keys()
    except Exception as e:
        print("Error: " + str(e))
        return []
    

def read_data():
    interfaces = getInterfaces()
    if len(interfaces) == 0 :
       print("No interfaces found")
       
    maxPacketInfo = 100
    totalPacketInfo = collections.deque(maxlen=maxPacketInfo)
    
    try:
        def packet_callback(pkt):
            totalPacketInfo.append(getPacketInfo.get(pkt))
                
        # capture is the live session on all interfaces in list 
        capture = pyshark.LiveCapture(list(interfaces))
        # most effeicnet way to apply function on packets, packet_count = 0/ " " for infinite
        capture.apply_on_packets(packet_callback, packet_count=200)
        capture.close()
        return totalPacketInfo
    
    except Exception as e:
        print("ErrorInRead: " + str(e) )
        
# main function
if __name__ == "__main__":
    packetInfo = read_data()
    
    # formatedPacketInfo = FormatDataPackets.formatPackets(packetInfo)
    # ScanPorts.scanPorts()
    
    
    
    
    
    
