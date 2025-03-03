def get(pkt):
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
            TCP_Packet(packetInfo, pkt)
        
        return packetInfo
    except Exception as e:
        print("ErrorInPacketInfo: " + str(e))
        return packetInfo
    
    
def TCP_Packet(packetInfo, pkt):
    try:
        packetInfo["Source"] = pkt.IP.src
        packetInfo["Destination"] = pkt.IP.dst
        packetInfo["Source Port"] = pkt.TCP.srcport
        packetInfo["Destination Port"] = pkt.TCP.dstport
        # if (pkt.TCP.analysis_acks_frame) and pkt.TCP.analysis_acks_frame is not None
        if hasattr(pkt.TCP, "analysis_acks_frame"):
            flags = pkt.TCP.flags,
            frame = pkt.TCP.analysis_acks_frame
            packetInfo["Flags"] = flags,frame
            
        else:
            packetInfo["Flags"] = pkt.TCP.flags
            
    except Exception as e:
        print("ErrorInTCPPacket: " + str(e))
        return packetInfo
    
def UDP_Packet(packetInfo, pkt):
    pass
        
    
def windowAveragePacketLength(window):
    totalPacketLength = 0
    for packet in window:
        totalPacketLength += int(packet["Length"])
    return totalPacketLength/len(window)


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

# TODO: Implement ackReplyCheck
def ackReplyCheck(window):
    # check if the packet is an ack or a reply
    pass
    # for packet in window:
    #     if ("Flags" not in packet):
    #         print("No Flags")
    #         return
            
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
    startTime = float(window[0]["Time"])
    for pktTime in window:
        pktTime = float(pktTime["Time"])
        pktTime = pktTime - startTime
    duration = float(window[-1]["Time"]) - startTime
    rate = len(window)/duration
    return rate

