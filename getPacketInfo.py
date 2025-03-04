import numpy as np
import TCP_Analysis

def get(pkt):
    # !Protocol List
    # ?TCP - Transmission Control Protocol - used for sending data, waatch for acks and replies ensuring there is no overloading of either 
    # ?UDP - User Datagram Protocol - used for sending data, check for suspicious data being sent
    # ?ICMP - Internet Control Message Protocol - used for sending error messages, check for suspicious data being sent
    # ?ARP - Address Resolution Protocol - used for mapping IP addresses to MAC addresses, check for suspicious malipulation of destonations
    # ?DNS - Domain Name System - used for translating domain names to IP addresses, check for suspicious data being sent
    # ?S7COMM - Siemens S7 Communication - used for communication with Siemens PLCs(industrial unit control) , check for any possibel tampering and unauthorised access
    # ?Modbus - Modbus Protocol - used for data transfer with PLCs, check for altered data being sent or any possibel tampering    
    
    
    
    # verage Packet Length	✅ Implemented	-
    # Deviation of Packet Length	✅ Implemented (log-normalized)	-
    # Packet Rate	⚠️ Broken calculation	✅ Fix ΔT calculations
    # Protocol Distribution (TCP, DNS, etc.)	✅ Implemented	-
    # TCP Flag Distribution (SYN%, PSH%, RST%)	✅ Implemented	-
    # SYN Flood Detection (SYN/ACK ratio)	✅ Implemented	-
    # PSH% (Potential Exfiltration)	✅ Implemented	-
    # DNS Query Frequency (Potential Tunneling)	❌ Missing	✅ Implement
    # Out-of-Order Packets Ratio	❌ Missing	✅ Implement
    # Retransmission Rate	❌ Missing	✅ Implement
    # Entropy Score for Data Payloads	❌ Missing	✅ Implement
    
    
    
    # Get the packet info 
    # (pkt.frame_info)- for general info: packet time, interface name etc
    # set all usefull info into a dictionary
    packetInfo = {}
    try: 
        packetInfo["Packet No."] = pkt.number
        packetInfo["Protocol"] = pkt.highest_layer
        packetInfo["Length"] = pkt.length
        packetInfo["Time"] = pkt.frame_info.time_epoch
        
        if pkt.highest_layer == "TCP":
            TCP_Analysis.TCP_Packet(packetInfo, pkt)    
        elif pkt.highest_layer == "UDP":
            pass
        elif pkt.highest_layer == "ICMP":
            pass
        elif pkt.highest_layer == "ARP":
            pass
        elif pkt.highest_layer == "DNS":
            pass
        elif pkt.highest_layer == "S7COMM":
            pass    
        elif pkt.highest_layer == "Modbus":
            pass
        
        
        return packetInfo
    except Exception as e:
        print("ErrorInPacketInfo: " + str(e))
        return packetInfo
    


def UDP_Packet(packetInfo, pkt):
    pass

# !-------------------General Analysis-----------------------------
def windowAveragePacketLength(window):
    totalPacketLength = 0
    for packet in window:
        totalPacketLength += int(packet["Length"])
    average = totalPacketLength/len(window)
    return average

def protocolList(window):
    # ?normalises the protocol count data into percentages
    protocolCount = {}
    for packet in window:
        if packet["Protocol"] in protocolCount:
            protocolCount[packet["Protocol"]] += 1
        else:
            protocolCount[packet["Protocol"]] = 1
    
    for protocol in protocolCount:
        protocolCount[protocol] = protocolCount[protocol]/len(window)
    return protocolCount
        

def windowDeviationPacketLength(window):
    # ?Uses Welford's algorithm to calc standard deviation
    n = 0
    mean = 0.0
    M2 = 0.0
    for packet in window:
        x = float(packet["Length"])
        n += 1
        delta = x - mean
        mean += delta / n
        delta2 = x - mean
        M2 += delta * delta2
    if n < 2:
        return 0.0
    stanrdDeviation = np.sqrt(M2 / (n - 1))
    stanrdDeviationNormal = float(np.log1p(stanrdDeviation))
    return stanrdDeviationNormal

def packetRate(window):
    if not window:
        return 0
    if len(window) == 1:
        return 1
    startTime = float(window[0]["Time"])
    
    for pktTime in window:
        pktTime = float(pktTime["Time"])
        pktTime = pktTime - startTime
        
    duration = float(window[-1]["Time"]) - startTime
    rate = len(window)/duration
    return rate


# !----------------------TCP Analysis---------------------------------
def ackReplyCheck(window, MaxSynCount = 5000, ratioThreshold = 0.8):
    synCount = 0 
    synAckCount = 0
    
    flagCounts = {
        "FIN Flag": 0,
        "SYN Flag": 0,
        "RST Flag": 0,
        "PSH Flag": 0,
        "ACK Flag": 0,
        "URG Flag": 0,
        "ECE Flag": 0,
        "CWR Flag": 0
    }
    
    totalTCPpackets = 0 

    for packet in window:
        if "Flags" not in packet:
            continue
    
        totalTCPpackets += 1

        
        if "SYN Flag" not in packet or "ACK Flag" not in packet:
            continue
    
        if packet["SYN Flag"] in packet and packet["ACK Flag"] in packet:
            if packet["SYN Flag"]==1 and packet["ACK Flag"] == 0:
                synCount += 1
            if packet["SYN Flag"]==1 and packet["ACK Flag"] == 1:
                synAckCount += 1
            
        for flag in flagCounts:
            if packet[flag] == 1:
                flagCounts[flag] += 1
                
    if totalTCPpackets > 0 :
        normalisedFlagCounts = {flag: count/totalTCPpackets for flag,count in flagCounts.items()}
    else:
        normalisedFlagCounts = {flag: 0.0 for flag in flagCounts.keys()}
        
    if synCount <= 0 : return 0,normalisedFlagCounts
    
    if synAckCount  < 1 :
        print("SYN Attack Guarentted")
        return 0,normalisedFlagCounts
    
    
    synAckRatio = synAckCount/synCount
    
    if synCount > MaxSynCount and synAckRatio < ratioThreshold:
        print("SYN Attack possible")
        return 1,normalisedFlagCounts
    else:
        return 0,normalisedFlagCounts
    
    
    