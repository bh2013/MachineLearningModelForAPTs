import numpy as np

# Assigns appropriate values to the packetInfo dictionary for ICMP packets
# !Done
def ICMP_Packet(packetInfo, pkt):
    try:

        packetInfo["Type"] = pkt.icmp.type
        packetInfo["Code"] = pkt.icmp.code
        if hasattr(pkt.icmp, "ip_ttl"):
            packetInfo["TimeToLive"] = pkt.icmp.ip_ttl
        else:
            packetInfo["TimeToLive"] = 0
    
        if hasattr(pkt.icmp, "ip_id"):
            packetInfo["Id"] = pkt.icmp.ip_id
        else:
            packetInfo["Id"] = 0
        # packetInfo["Payload"] = pkt.icmp.data.data
        
       
    except AttributeError:
        print("AttributeError in ICMP")
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
            if packet["TimeToLive"] == 0:
                continue
            ICMPCount += 1
            TTLCount += float(packet["TimeToLive"])
            
    if ICMPCount == 0:
        return 0
    
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
        if packet["Protocol"] == "ICMP" and packet["Id"] != 0:
            
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
    
    return avgTripStats 

# Calculates the ratio of ICMP types in the window and returns them in a list with a % 
# !Done
def typeRatios(window):
    types = {
        "0":0,
        "3":0,
        "5":0,
        "8":0,
        "Unknown":0
    }
    ICMPCount = 0 
    
    for packets in window:
        if packets["Protocol"] == "ICMP":
            ICMPCount += 1
            type = packets["Type"]
            if type in types:
                types[type] += 1
            else:
                types["Unknown"] += 1
           
                   
    if ICMPCount == 0:
        return 0,0,0,0,0
     
    returnTypes = []
    for each in types:
        types[each] = types[each] / ICMPCount
        

    for each in types:
        returnTypes.append(types[each])

    sortedTypes = {k: types[k] for k in sorted(types)}

    return sortedTypes

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