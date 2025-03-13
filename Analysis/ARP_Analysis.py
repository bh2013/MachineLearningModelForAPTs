from Analysis import ipList

def ARP_Packet(packetInfo, pkt):
    try:
        packetInfo["Operation"] = pkt.arp.opcode
        packetInfo["SourceMAC"] = pkt.arp.src_hw_mac
        packetInfo["DestinationMAC"] = pkt.arp.dst_hw_mac
        packetInfo["SourceIP"] = pkt.arp.src_proto_ipv4
        packetInfo["DestinationIP"] = pkt.arp.dst_proto_ipv4
        return packetInfo

    except Exception as e:
        print("ErrorInARPPacket: " + str(e))
        return packetInfo
    
    
def ReplyRequestDiffernce(window):
    request = 0
    reply = 0
    arpCount = 0
    for packet in window:
        if packet["Protocol"] == "ARP":
            arpCount += 1
            if "Operation" in packet:
                opCode = int(packet["Operation"])
                if opCode== 1:
                    request += 1
                elif opCode == 2:
                    reply += 1
                    
    
    if request == 0 or reply == 0:
        return 0
    
    difference = abs(request - reply)
    
    return difference / max(request, reply, 1)  # Normalized difference



ARPSpoofTracker = {}
def DetectARPSpoof(window):
    global ARPSpoofTracker

    for packet in window:
        if packet["Protocol"] == "ARP":
            if  "SourceIP" in packet and "SourceMAC" in packet:
                ip = packet["SourceIP"]
                mac = packet["SourceMAC"]
                
                if ip in ARPSpoofTracker:
                    if mac != ARPSpoofTracker[ip]:
                        return 1
                else:
                    ARPSpoofTracker[ip] = mac    
    return 0


def unkownIPFlag(window):
    knownIps = ipList.IpsPorts()
    for packet in window:
        if packet["SourceIP"] not in knownIps:
            print("Unknown ARP IP")
            return 1
        elif packet["DestinationIP"] not in knownIps:
            print("Unknown ARP IP")
            return 1
    return 0

