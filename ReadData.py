#This file will act as a wireshark to run and read the data in real time 

# Libriaries 
import psutil
import pyshark
# ---------------------z
# files to import 
import ScanPorts
import UnitTest
# ---------------------


def getInterfaces():
    
    try:
        address = psutil.net_if_addrs()
        return address.keys()
    except Exception as e:
        print("Error: " + str(e))
        return []
    
    
# TODO:
    def GetSystemInfo():
        # Get the system info
        # get Mac address
        pass

        
    def CommonAddresses():
        # Get the most common addresses 
        pass


def getPacketInfo(pkt):
    # Get the packet info 
    # (pkt.frame_info)- for general info: packet time, interface name etc

    # set all usefull info into a dictionary
    packetInfo = {}

    try: 
        packetInfo["Source"] = pkt.ip.src
        packetInfo["Destination"] = pkt.ip.dst
        packetInfo["Time"] = pkt.frame_info.time
        packetInfo["Length"] = pkt.length
        packetInfo["Protocol"] = pkt.highest_layer

        
        return packetInfo
    except Exception as e:
        print("ErrorInPacketInfo: " + str(e))
        return packetInfo
    

            
    # time stamp for packet
    # epochTime = pkt.frame_info.time_epoch
    # print("Epoch Time: " + str(epochTime))

    # layers = pkt.layers
    # ETH = layers[0] - Link layer 
    # IP = layers[1] - Network layer
    # ... etc
    # for layer in layers:
    #     print(layer)
    
def read_data():
    
    interfaces = getInterfaces()
    if len(interfaces) == 0 :
       print("No interfaces found")
       UnitTest.TestPacket().test_getInterfaces()

    # Capture the packets
    try:
        print(interfaces)
        
        def print_callback(pkt):
                # packetList.append(pkt)
                TotalPacketInfo = getPacketInfo(pkt)
                print(TotalPacketInfo)

        # capture is the live session on all interfaces in list 
        capture = pyshark.LiveCapture(interfaces)
        # most effeicnet way to apply function on packets, packet_count = 0/ " " for infinite
        capture.apply_on_packets(print_callback, timeout=2, packet_count=12)
        capture.close
        
    except Exception as e:
        print("ErrorInRead: " + str(e))
        
# main function
if __name__ == "__main__":
    read_data()
    # ScanPorts.scanPorts()
    
    
    
    
    
    
