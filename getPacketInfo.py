import numpy as np
import TCP_Analysis
import ipList
import DNS_Analysis

def get(pkt):
    # !Protocol List
    # ?TCP - Transmission Control Protocol - used for sending data, waatch for acks and replies ensuring there is no overloading of either 
    # ?UDP - User Datagram Protocol - used for sending data, check for suspicious data being sent- shouldnt be any so flag them if there are 
    # ?ICMP - Internet Control Message Protocol - used for sending error messages, check for suspicious data being sent
    # ?ARP - Address Resolution Protocol - used for mapping IP addresses to MAC addresses, check for suspicious malipulation of destonations
    # ?DNS - Domain Name System - used for translating domain names to IP addresses, check for suspicious data being sent
    # ?S7COMM - Siemens S7 Communication - used for communication with Siemens PLCs(industrial unit control) , check for any possibel tampering and unauthorised access
    # ?Modbus - Modbus Protocol - used for data transfer with PLCs, check for altered data being sent or any possibel tampering    
    
    # Get the packet info 
    # (pkt.frame_info)- for general info: packet time, interface name etc
    # set all usefull info into a dictionary
    packetInfo = {}
    try: 
        packetInfo["Packet No."] = pkt.number
        packetInfo["Protocol"] = pkt.highest_layer
        packetInfo["Length"] = pkt.length
        packetInfo["Time"] = pkt.frame_info.time_epoch
        if(hasattr(pkt,"ip")):
            packetInfo["Source"] = pkt.ip.src
            packetInfo["Destination"] = pkt.ip.dst

        
        if pkt.highest_layer == "TCP":
            TCP_Analysis.TCP_Packet(packetInfo, pkt)
        elif pkt.highest_layer == "UDP":
            pass
        elif pkt.highest_layer == "ICMP":
            pass
        elif pkt.highest_layer == "ARP":
            pass
        elif pkt.highest_layer == "DNS":
            DNS_Analysis.DNS_Packet(packetInfo, pkt)
        elif pkt.highest_layer == "S7COMM":
            pass    
        elif pkt.highest_layer == "Modbus":
            pass
        return packetInfo
    
    
    except Exception as e:
        print("ErrorInPacketInfo: " + str(e))
        return packetInfo
    
def UDP_Packet(packetInfo, pkt):
    pass

# !-------------------General Analysis-----------------------------
def windowAveragePacketLength(window):
    totalPacketLength = 0
    for packet in window:
        totalPacketLength += int(packet["Length"])
        
        
    average = totalPacketLength/len(window)
    return average

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
    # ?Uses Welford's algorithm to calc standard deviation
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
    stanrdDeviation = np.sqrt(M2 / (n - 1))
    stanrdDeviationNormal = float(np.log1p(stanrdDeviation))
    return stanrdDeviationNormal

def packetRate(window):
    if not window:
        return 0
    startTime = float(window[0]["Time"])

    if len(window) == 1:
        return 1
    
    endTime = float(window[-1]["Time"])
    durationOfWidnow = endTime - startTime
    # calculting average packet time for window, and standard deviation between packets
    arrivalTimes = [float(packet["Time"]) for packet in window]
    # calcuates the time between packets 
    diffInTimeBetweenPackets = np.diff(arrivalTimes)
    
    meanTimeDifferencePerPacket = np.mean(diffInTimeBetweenPackets)
    standardDeviationBetweenPackets = np.std(diffInTimeBetweenPackets)
    
    # calculate entrop of the time between packets
    historgram, bin_edge = np.histogram(diffInTimeBetweenPackets, bins = 10, density=True)
    historgram = historgram/np.sum(historgram)
    historgram = historgram[historgram >0]
    entropy = -np.sum(historgram * np.log2(historgram))
    
    if durationOfWidnow == 0:
        return len(window)
        
    packetRate = len(window)/durationOfWidnow
        
    return float(packetRate),float(durationOfWidnow),float(meanTimeDifferencePerPacket),float(standardDeviationBetweenPackets),float(entropy)

def outOfOrderPacketCount(window):
    outOfOrderPacketCount = 0
    for packet in window:
        if window.index(packet) == 0:
            continue
        
        if packet["Packet No."] < window[window.index(packet) - 1]["Packet No."]:
            outOfOrderPacketCount += 1
            
    outOfOrderRatio = outOfOrderPacketCount/len(window)
    return (outOfOrderRatio)


def knownIpCheck(window):

    ListOfKnowIps = {}
    ListOfKnowIps = ipList.IpsPorts()

    unkownDomain = {}
    for packet in window:
        if "Source" not in packet or "Destination" not in packet:
            continue  
        
        if packet["Source"] not in ListOfKnowIps:
            if packet["Source"] not in unkownDomain:
                unkownDomain[packet["Source"]] = 1
            else:
                unkownDomain[packet["Source"]] += 1
        if packet["Destination"] not in ListOfKnowIps:
            if packet["Destination"] not in unkownDomain:
                unkownDomain[packet["Destination"]] = 1
            else:   
                unkownDomain[packet["Destination"]] += 1

        
    return unkownDomain

# !doesnt Work
def allInOneLoop(window):
    # total length of all packets in the window
    totalPacketLength = 0
    
    # dictionary of all protocols in the window and their count
    protocolCount = {}
        
    # standard deviation of packet length variables
    n = 0
    mean = 0.0
    M2 = 0.0
    
    # start time of the window
    startTime = float(window[0]["Time"])
    endTime = float(window[-1]["Time"])

    durationOfWindow = endTime - startTime
    
    arrivalTimes = []
    
    for packet in window:
        totalPacketLength += int(packet["Length"])
        
        if packet["Protocol"] in protocolCount:
            protocolCount[packet["Protocol"]] += 1
        else:
            protocolCount[packet["Protocol"]] = 1
    
        x = float(packet["Length"])
        n += 1
        delta = x - mean
        mean += delta / n
        delta2 = x - mean
        M2 += delta * delta2
        
        arrivalTimes.append(float(packet["Time"]))
        if window.index(packet) == 0:
            outOfOrderPacketCount = 0
        
        if packet["Packet No."] < window[window.index(packet) - 1]["Packet No."]:
            outOfOrderPacketCount += 1
            
    # Flow Stats
    diffInTimeBetweenPackets = np.diff(arrivalTimes)
    
    meanTimeDifferencePerPacket = np.mean(diffInTimeBetweenPackets)
    standardDeviationBetweenPackets = np.std(diffInTimeBetweenPackets)
    
    # calculate entrop of the time between packets
    historgram, bin_edge = np.histogram(diffInTimeBetweenPackets, bins = 10, density=True)
    historgram = historgram/np.sum(historgram)
    historgram = historgram[historgram >0]
    entropy = -np.sum(historgram * np.log2(historgram))


    packetRate = len(window)/durationOfWindow
    
    if n < 2:
        print("Standard Deviation error")
        
    
    stanrdDeviationLength = np.sqrt(M2 / (n - 1))
    stanrdDeviationLengthNormal = float(np.log1p(stanrdDeviationLength))

    
    for protocol in protocolCount:
        protocolCount[protocol] = protocolCount[protocol]/len(window)
    
    average = totalPacketLength/len(window)
    
    list = average,protocolCount,stanrdDeviationLengthNormal,durationOfWindow,packetRate,meanTimeDifferencePerPacket,standardDeviationBetweenPackets,entropy 
    
    
    return list


    
    
    