import numpy as np

# Assigns appropriate values to the packetInfo dictionary for ICMP packets
# !Done
def ICMP_Packet(packetInfo, pkt):
    try:

        packetInfo["Type"] = pkt.icmp.type
        packetInfo["Code"] = pkt.icmp.code
        packetInfo["TimeToLive"] = pkt.icmp.ip_ttl
        packetInfo["Id"] = pkt.icmp.ip_id
        # packetInfo["Payload"] = pkt.icmp.data.data
        
       
    except AttributeError:
        print("AttributeError")
        pass
    except Exception as e:
        print("ErrorInICMPPacket: " + str(e))
        
    return packetInfo

# Calculates average Time to live of ICMP packets
# !Done
def TTLAvg(window):
    TTLCount = 0
    ICMPCount = 0
    
    for packet in window:
        if packet["Protocol"] == "ICMP":
            ICMPCount += 1
            TTLCount += float(packet["TimeToLive"])
            
    avgTTL = TTLCount / ICMPCount
    return avgTTL

# Calculates the response ratio of ICMP packets by collecting requests and replies and calculating the ratio, usally 0 with this data set but could be useful in the future
# !Done
def ResponseRatio(window):
    ICMPStatusCount = {
        "Request": 0,
        "Reply": 0
    }

    for packet in window:
        if packet["Protocol"] == "ICMP":
            ICMPtype = packet["Type"]
            if ICMPtype == 8:
                ICMPStatusCount["Request"] +=1
            elif ICMPtype == 0:
                ICMPStatusCount["Reply"] +=1
                
    if ICMPStatusCount["Reply"] == 0:
        return ICMPStatusCount["Request"]
    else:
        return (ICMPStatusCount["Request"] / ICMPStatusCount["Reply"])

# ?data set seems to have no reply reuqest so suspicous, however if ever used it might be useful to track
def RoundTrips(window):
    replyCheck= {}
    allTrips = []
    ICMPCount = 0 
    for packet in window:
        if packet["Protocol"] == "ICMP":
            ICMPCount += 1
            ICMPtype = packet["Type"]
            ICMPid = packet["Id"] 
            time = packet["Time"]
            if ICMPtype == 8:
                print("Request")
                replyCheck[ICMPid] = time
            elif ICMPtype == 0 and ICMPid in replyCheck:
                roundTripTime = time - replyCheck(ICMPid,time)
                allTrips.append(roundTripTime)

    if len(allTrips) == 0:
        return 0,0,0,0
    
    mean = np.mean(allTrips)
    largestTime = np.max(allTrips)
    smallestTime = np.min(allTrips)
    deviationBetweenTrips = np.std(allTrips)

    avgTripStats = mean, largestTime, smallestTime, deviationBetweenTrips
    
    return ICMPCount,avgTripStats 

# Calculates the ratio of ICMP types in the window and returns them in a list with a % 
# !Done
def typeRatios(window):
    types = {}
    ICMPCount = 0 
    
    for packets in window:
        if packets["Protocol"] == "ICMP":
            ICMPCount += 1
            type = packets["Type"]
            if type in types:
                types[type] += 1
            else:
                types[type] = 1
                
    for each in types:
        types[each] = types[each] / ICMPCount
        
    return types

# Checks for ICMP redirects and unreachable packets w/ counts
# !Done
def TypeChecks(window):
    redirect = 0
    unreachable = 0
    ICMPCount = 0
    for packet in window:
        if packet["Protocol"] == "ICMP":
            ICMPCount += 1
            if packet["Type"] == 5:
                redirect += 1
            if packet["Type"] == 3:
                unreachable += 1
                
    
    return redirect,unreachable

# Checks for fragmentation in ICMP packets, all packets seem to be typoe 3, need to investigate further
def fragmentationCheck(window):
    fragmentation = 0
    for packet in window:
        if packet["Protocol"] == "ICMP":
            if packet["Type"] == 3:
                fragmentation += 1
    
    return fragmentation