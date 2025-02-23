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
            packetInfo["Source"] = pkt.IP.src
            packetInfo["Destination"] = pkt.IP.dst
            packetInfo["Source Port"] = pkt.TCP.srcport
            packetInfo["Destination Port"] = pkt.TCP.dstport
            packetInfo["Flags"] = pkt.TCP.flags
        return packetInfo
    except Exception as e:
        print("ErrorInPacketInfo: " + str(e))
        return packetInfo
    
def windowAveragePacketLength(window):
    totalPacketLength = 0
    for packet in window:
        totalPacketLength += int(packet["Length"])
    return totalPacketLength/len(window)


def protocolList(window):
    protocolCount = {}
    for packet in window:
        if packet["Protocol"] in protocolCount:
            protocolCount[packet["Protocol"]] += 1
        else:
            protocolCount[packet["Protocol"]] = 1
    
    for protocol in protocolCount:
        protocolCount[protocol] = protocolCount[protocol]/len(window)
    
    print(protocolCount)
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

