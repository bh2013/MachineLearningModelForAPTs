import Analysis.ipList as ipList
import numpy as np



def knownIpCheck(window):

    knownIps = set(ipList.IpsPorts())
    unkownIps = set()
    
    for packet in window:
        if "Source" in packet and packet["Source"] not in knownIps:
            unkownIps.add(packet["Source"])
        if "Destination" in packet and packet["Destination"] not in knownIps:
            unkownIps.add(packet["Destination"])
        
    return len(unkownIps)

def protocolList(window):
    # ?normalises the protocol count data into percentages
    protocolCount = {
        "TCP": 0,
        "ICMP": 0,
        "ARP": 0,
        "DNS": 0,
        "MODBUS": 0,
        "S7COMM": 0,
        "DATA": 0,
        "Unkown": 0
    }
    # create dict with all tracked protocols adding unkown to a list of unkown protocols and counts 
    
    for packet in window:
        if packet["Protocol"] in protocolCount:
            protocolCount[packet["Protocol"]] += 1
        else:
            protocolCount["Unkown"] = 1

    for protocol in protocolCount:
        protocolCount[protocol] = protocolCount[protocol]/len(window)
        
    # Sort alphetcially
    protocolCount = dict(sorted(protocolCount.items(), key=lambda item: item[0]))
    
    return protocolCount
        
def outOfOrderPacketCount(window):            
    total = sum(1 for i in range(1, len(window)) if window[i]["Packet No."] < window[i - 1]["Packet No."])
    return total


def packetRate(window):
    if not window:
        return 0,0,0,0
    
    startTime = float(window[0]["Time"])

    if len(window) == 1:
        return 1
    
    endTime = float(window[-1]["Time"])
    
    durationOfWidnow = endTime - startTime
    
    # calculting average packet time for window, and standard deviation between packets
    times = [float(packet["Time"]) for packet in window]
    
    # calcuates the time between packets 
    diffInTimeBetweenPackets = np.diff(times) if len(times) > 1 else [1]
    
    meanTimeDifferencePerPacket = np.mean(diffInTimeBetweenPackets)
    standardDeviationBetweenPackets = np.std(diffInTimeBetweenPackets)
    

    

    if durationOfWidnow == 0:
        return len(window)
    
    packetRate = len(window)/durationOfWidnow
    
    return {
        float(packetRate),
        float(durationOfWidnow),
        float(meanTimeDifferencePerPacket),
        float(standardDeviationBetweenPackets),
        }

    
def windowAveragePacketLength(window):  
    average = sum(int(packet["Length"]) for packet in window)/len(window)
    return float(average)

def MinMaxLength(window):
    lengths = [int(packet["Length"]) for packet in window]
    return min(lengths), max(lengths)


def windowDeviationPacketLength(window):
    if len(window) == 0:
        return 0
    lengths = [float(packet["Length"]) for packet in window]
    return float(np.std(lengths))


