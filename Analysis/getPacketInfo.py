import numpy as np
from Analysis import S7_Analysis
import Analysis.TCP_Analysis as TCP_Analysis

import Analysis.DNS_Analysis as DNS_Analysis
import Analysis.ARP_Analysis as ARP_Analysis
import Analysis.ICMP_Analysis as ICMP_Analysis
import Analysis.Modbus_Analysis as Modbus_Analysis

def get(pkt):
    # !Protocol List
    # ?TCP - Transmission Control Protocol - used for sending data, waatch for acks and replies ensuring there is no overloading of either 
    # ?UDP - User Datagram Protocol - used for sending data, check for suspicious data being sent- shouldnt be any so flag them if there are 
    # ?ICMP - Internet Control Message Protocol - used for sending error messages, check for suspicious data being sent
    # ?ARP - Address Resolution Protocol - used for mapping IP addresses to MAC addresses, check for suspicious malipulation of destonations
    # ?DNS - Domain Name System - used for translating domain names to IP addresses, check for suspicious data being sent
    # ?S7COMM - Siemens S7 Communication - used for communication with Siemens PLCs(industrial unit control) , check for any possibel tampering and unauthorised access
    # ?Modbus - Modbus Protocol - used for data transfer with PLCs, check for altered data being sent or any possibel tampering    
    
    # Get the packet info 
    # (pkt.frame_info)- for general info: packet time, interface name etc
    # set all usefull info into a dictionary
    packetInfo = {}
    try: 
        packetInfo["Packet No."] = pkt.number
        packetInfo["Protocol"] = pkt.highest_layer
        packetInfo["Length"] = pkt.length
        packetInfo["Time"] = pkt.frame_info.time_epoch
        
        
        if(hasattr(pkt,"ip")):
            packetInfo["Source"] = pkt.ip.src
            packetInfo["Destination"] = pkt.ip.dst
        
        if pkt.highest_layer == "TCP":
            TCP_Analysis.TCP_Packet(packetInfo, pkt)
        elif pkt.highest_layer == "ICMP":
            ICMP_Analysis.ICMP_Packet(packetInfo, pkt)
        elif pkt.highest_layer == "ARP":
            ARP_Analysis.ARP_Packet(packetInfo, pkt)
        elif pkt.highest_layer == "DNS":
            DNS_Analysis.DNS_Packet(packetInfo, pkt)
        elif pkt.highest_layer == "S7COMM":
            S7_Analysis.S7_Packet(packetInfo, pkt) 
        elif pkt.highest_layer == "MODBUS":
            Modbus_Analysis.Modbus_Packet(packetInfo, pkt)
        return packetInfo
    
    
    except Exception as e:
        print("ErrorInPacketInfo: " + str(e))
        return packetInfo
    


    
    