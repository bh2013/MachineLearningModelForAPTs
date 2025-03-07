
def TCP_Packet(packetInfo, pkt):
    # Flag Info 0x000
    # ? 0x001 = FIN, Finish
    # ? 0x002 = SYN, Syncronize
    # ? 0x004 = RST, Reset
    # ? 0x008 = PSH, Push
    # ? 0x010 = ACK, Acknowledge
    # ? 0x020 = URG, Urgent
    # ? 0x040 = ECE, Explicit Congestion Notification 
    # ? 0x080 = CWR, Congestion Window Reduced
    
    
    try:
        packetInfo["Source Port"] = pkt.TCP.srcport
        packetInfo["Destination Port"] = pkt.TCP.dstport
        packetInfo["Sequence Number"] = pkt.TCP.seq
        packetInfo["Acknowledgment Number"] = pkt.TCP.ack
        packetInfo["Window Size"] = pkt.TCP.window_size
        packetInfo["Payload Length"] = pkt.TCP.len
        tcpFlags = int(pkt.TCP.flags,16)
        packetInfo["Flags"] = tcpFlags
        
        
        # !1 or 0 for anlysis on isolation forrest, flagging differnt occurences 
        packetInfo["FIN Flag"] = 1 if bool(tcpFlags & 0x001) else 0 # Can be used to slow the server down with FIN floods
        packetInfo["SYN Flag"] = 1 if bool(tcpFlags & 0x002) else 0  # Can also be used  to slow down the server with 
        packetInfo["RST Flag"] = 1 if bool(tcpFlags & 0x004)  else 0 # Can be reset to distrubt attacks 
        packetInfo["PSH Flag"] = 1 if bool(tcpFlags & 0x008)  else 0 # Can be used for exfiltration, must watch 
        packetInfo["ACK Flag"] = 1 if bool(tcpFlags & 0x010)  else 0 # Used to check if the packet is an ACK, Flood Attacks 
        packetInfo["URG Flag"] = 1 if bool(tcpFlags & 0x020)  else 0 # Maybe used for evading IDS
        packetInfo["ECE Flag"] = 1 if bool(tcpFlags & 0x040)  else 0 # Unkley to be used for an attack as its used for congestion control
        packetInfo["CWR Flag"] = 1 if bool(tcpFlags & 0x080)  else 0 # Also unlikey as part of congestion control
        
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
    