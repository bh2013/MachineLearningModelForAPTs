
import ipList

def DNS_Packet(packetInfo, pkt):
    try:
        # print(dir(pkt.DNS))
        packetInfo["Name"] = pkt.DNS.qry_name
        packetInfo["Type"] = pkt.DNS.qry_type
        packetInfo["Class"] = pkt.DNS.qry_class
        packetInfo["Answers"] = pkt.DNS.count_answers
        
        
        # print(dir(pkt.DNS.a))
        if packetInfo["Type"] == "A":
            print(packetInfo["Name"])
        
            
    except Exception as e:
        print("ErrorInDNSPacket: " + str(e))
        return packetInfo
    
        
def unauthorisedDomainCount(window):
    # knownIPsPorts = ipList.IpsPorts()
    # unkonwnDomainCount = {}
  
    # for packet in window:
    #     if packet["Protocol"] == "DNS":
    #         for device in knownIPsPorts:
    #             if packet["Name"] != device["ip"]:
    #                 unkonwnDomainCount[packet["Name"]] += 1
    pass
    
    # return unkonwnDomainCount
          

    
    
    