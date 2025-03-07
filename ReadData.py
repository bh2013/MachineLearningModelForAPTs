#This file will act as a wireshark to run and read the data in real time 

# Pcap file with Industrial/scada rules https://www.netresec.com/?page=PCAP4SICS, 4SICS-GeekLounge-151022.pcap, 4SICS-GeekLounge-151021, 4SICS-GeekLounge-151020.pcap

# Libriaries 
import psutil
import pyshark
import collections
# ---------------------z
# files to import 
import getPacketInfo
import TCP_Analysis
import DNS_Analysis
import ipList
# ---------------------

# TODO 
# 2.DNS Query Frequency (Potential Tunneling)	
# 4.Retransmission Rate	
# 6.Record all the IP addresses and ports that the device is communicating with, from the pcap file site 
# 7/ Make get packetData more efficient, and add more protocols


count = 0 
def windowCount():
    global count
    count = count + 1
    return count
    
def getWindowsData(window):
    # sets first window to none
    prevWindow = None 
    def packetGet(pkt , window = window):
        # sets as a non local to allow it to be changed for each windoqw
        # important for processing previous window
        nonlocal prevWindow   
        # gets the packet info and removes any info that isnt needed 
        pkt = getPacketInfo.get(pkt)
        # adds the packet to the current window
        window.append(pkt)
        
        # if window is full then analyse the window
        if len(window) == window.maxlen:
            # gets the number of windows
            count = int(windowCount())
            # if its 1 its the first widnow so no previous, only analyse the current window
            # !important as can catch problems on start, eg first packet doing something malicious
            # ?mayne this isnt needed tho, should be able to catch soemthing suspicious in the first window when sent to ML model
            # Take note of this 
            if count == 1:
                # !First Window, can't compare to previous
                analysis = analyzeWindow(prevWindow,window)
                print(analysis)
                prevWindow = window.copy()
                window.clear()
                return
            else:
                # otherwise both windows are wanting to be used for comparisons to be made 
                analysis = analyzeWindow(prevWindow,window)
                print(analysis)
                prevWindow = window.copy()
            window.clear()
    return packetGet

def analyzeWindow(prevWindow,window):
# checks if the window is the first window
    if prevWindow == None:
        #Average packet length
        averagePacketLength = getPacketInfo.windowAveragePacketLength(window)
        #Lists all protocols and returns them as perctages 
        protocolList = getPacketInfo.protocolList(window)
        #Gets stats on the rates of packets, packets rate, window length, entropy of the window's packet intervals  
        FlowStats = getPacketInfo.packetRate(window)
        # ?gets the standard deviation of the packet length, not sure if usefull 
        deviationOfPacketLength = getPacketInfo.windowDeviationPacketLength(window)
        outOfOrderPacketRatio = getPacketInfo.outOfOrderPacketCount(window)
        # if the packet is tcp then check its flags, and replies, if tcpAnalysisSYNAttack is 1 then its a SYN attack
        tcpAnalysisSYNAttack,tcpAnalysisFlagDistrabution = TCP_Analysis.ackReplyCheck(window)
        unkownIps = getPacketInfo.knownIpCheck(window)

        return averagePacketLength,outOfOrderPacketRatio,FlowStats,tcpAnalysisSYNAttack,protocolList,tcpAnalysisFlagDistrabution,unkownIps
    else:    
        averagePacketLength = getPacketInfo.windowAveragePacketLength(window)
        protocolList = getPacketInfo.protocolList(window)
        FlowStats = getPacketInfo.packetRate(window)
        deviationOfPacketLength = getPacketInfo.windowDeviationPacketLength(window)
        outOfOrderPacketRatio = getPacketInfo.outOfOrderPacketCount(window)
        tcpAnalysisSYNAttack,tcpAnalysisFlagDistrabution = TCP_Analysis.ackReplyCheck(window)
        unkownIps = getPacketInfo.knownIpCheck(window)

        allVars = averagePacketLength,deviationOfPacketLength,outOfOrderPacketRatio,FlowStats,tcpAnalysisSYNAttack,protocolList,tcpAnalysisFlagDistrabution,unkownIps
        
        return allVars
        
# main function
if __name__ == "__main__":
# ?Can be changed to just capture on an interface, but for now just using a file

    allowedDomains = {}
    maxWindow = 1000
    windowDataInfo = collections.deque(maxlen=maxWindow)
    capture = pyshark.FileCapture("FileData/4SICS-GeekLounge-151021.pcap")
    window = getWindowsData(windowDataInfo)
    # !set to 0 to make constant or just choose a big number, less than the size of pcap file 
    capture.apply_on_packets(window,packet_count=15000)
    capture.close()
    
    
    
    
    
