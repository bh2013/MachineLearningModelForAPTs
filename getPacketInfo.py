import TCP_Analysis

def get(pkt):
    
    
    # !Protocol List
    # TCP - Transmission Control Protocol - used for sending data, waatch for acks and replies ensuring there is no overloading of either 
    # UDP - User Datagram Protocol - used for sending data, check for suspicious data being sent
    # ICMP - Internet Control Message Protocol - used for sending error messages, check for suspicious data being sent
    # ARP - Address Resolution Protocol - used for mapping IP addresses to MAC addresses, check for suspicious malipulation of destonations
    # DNS - Domain Name System - used for translating domain names to IP addresses, check for suspicious data being sent
    # S7COMM - Siemens S7 Communication - used for communication with Siemens PLCs(industrial unit control) , check for any possibel tampering and unauthorised access
    # Modbus - Modbus Protocol - used for data transfer with PLCs, check for altered data being sent or any possibel tampering
    
    
    
    
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
        
        return packetInfo
    except Exception as e:
        print("ErrorInPacketInfo: " + str(e))
        return packetInfo
    


def UDP_Packet(packetInfo, pkt):
    pass
        
def windowAveragePacketLength(window):
    totalPacketLength = 0
    for packet in window:
        totalPacketLength += int(packet["Length"])
    average = totalPacketLength/len(window)
    normalAVG = int(average)
    average = normalAVG - average
    average = average * 1000
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
    return M2 / (n - 1)  

def ackReplyCheck(window, MaxSynCount = 1000, ratioThreshold = 0.5):
    synCount = 0 
    synAckCount = 0

    for packet in window:
        if "Flags" not in packet:
            continue
        if "SYN Flag" not in packet or "ACK Flag" not in packet:
            continue
        
        if packet["SYN Flag"]==1 and packet["ACK Flag"] == 0:
            synCount += 1
        
        if packet["SYN Flag"]==1 and packet["ACK Flag"] == 1:
            synAckCount += 1
            

    if synCount < 0 : return 0
    if synAckCount  < 1 : return 0
    
    synAckRatio = synAckCount/synCount
    print(synAckRatio)

    if synCount > MaxSynCount and synAckRatio < ratioThreshold:
        return 1
    else:
        return 0

                    
   

    #     if(packet["Flags"] == "0x0010"): # ACK
    #         print("ACK")
    #         print(packet["Flags"])
    #     elif(packet["Flags"] == "0x0011"): # Fin and PSH
    #         print("ACK and PSH")
    #         print(packet["Flags"])
    #     elif(packet["Flags"] == "0x0012"):
    #         print("ACK and SYN")
    #         print(packet["Flags"])
        
    
    
    # if the packet is an ack, check if it is a reply to a packet in the window if not check in previous window 
    # if the packet is a reply, check if it is a reply to a packet in the previous window or this widnow
    # if the packet is neither, check if it is a new packet 
    pass


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

