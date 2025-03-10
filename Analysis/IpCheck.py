import Analysis.ipList as ipList
def knownIpCheck(window):

    knownIps = set(ipList.IpsPorts())
    unkownIps = set()
    
    for packet in window:
        if "Source" in packet and packet["Source"] not in knownIps:
            unkownIps.add(packet["Source"])
        if "Destination" in packet and packet["Destination"] not in knownIps:
            unkownIps.add(packet["Destination"])
        
    return len(unkownIps)
