
# ! extra packet info
def DNS_Packet(packetInfo, pkt):
    try:
        # print(dir(pkt.DNS))
        packetInfo["Name"] = pkt.DNS.qry_name
        packetInfo["Type"] = pkt.DNS.qry_type
        packetInfo["Class"] = pkt.DNS.qry_class
        packetInfo["Answers"] = pkt.DNS.count_answers
        
        
    except AttributeError:
        pass
    except Exception as e:
        print("ErrorInDNSPacket: " + str(e))
    return packetInfo
    
def DNSQueryRatePerSecond(window):
    DNSCount = 0
    windowDuration = float(window[-1]["Time"]) - float( window[0]["Time"])
    
    DNSCount = sum(1 for packet in window if packet["Protocol"] == "DNS")

    DNSrate = DNSCount / windowDuration
            
    return DNSrate

def DNSResponse(window):
    responseCount = sum(1 for packet in window if packet["Protocol"] == "DNS" and int(packet["Answers"]) > 0)
    return responseCount    
    
def dnsAvgQueryLength(window):
    DNScount = 0
    for packet in window:
        if packet["Protocol"] == "DNS":
            DNScount += 1
            queryLength = packet["Length"]