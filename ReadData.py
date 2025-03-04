#This file will act as a wireshark to run and read the data in real time 

# Pcap file with Industrial/scada rules https://www.netresec.com/?page=PCAP4SICS, 4SICS-GeekLounge-151022.pcap, 4SICS-GeekLounge-151021, 4SICS-GeekLounge-151020.pcap

# Libriaries 
import psutil
import pyshark
import collections
# ---------------------z
# files to import 
import getPacketInfo
# ---------------------

# TODO 

# 1.Packet Rate - Fix ΔT calculations
# 2.DNS Query Frequency (Potential Tunneling)	
# 3.Out-of-Order Packets Ratio	
# 4.Retransmission Rate	
# 5.Entropy Score for Data Payloads




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
        
        
        # if window is full then analyze the window
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
        averagePacketLength = getPacketInfo.windowAveragePacketLength(window)
        protocolList = getPacketInfo.protocolList(window)
        packetRate = getPacketInfo.packetRate(window)
        deviationOfPacketLength = getPacketInfo.windowDeviationPacketLength(window)
        tcpAnalysis = getPacketInfo.ackReplyCheck(window)
        return averagePacketLength,protocolList,packetRate,deviationOfPacketLength,tcpAnalysis
    else:    
        averagePacketLength = getPacketInfo.windowAveragePacketLength(window)
        protocolList = getPacketInfo.protocolList(window)
        packetRate = getPacketInfo.packetRate(window)
        deviationOfPacketLength = getPacketInfo.windowDeviationPacketLength(window)
        tcpAnalysisSYNAttack,tcpAnalysisFlagDistrabution = getPacketInfo.ackReplyCheck(window)
        return averagePacketLength,protocolList,packetRate,deviationOfPacketLength,tcpAnalysisSYNAttack,tcpAnalysisFlagDistrabution
        
# main function
if __name__ == "__main__":
# ?Can be changed to just capture on an interface, but for now just using a file
    maxWindow = 5000
    windowDataInfo = collections.deque(maxlen=maxWindow)
    capture = pyshark.FileCapture("FileData/4SICS-GeekLounge-151020.pcap")
    window = getWindowsData(windowDataInfo)
    # !set to 0 to make constant or just choose a big number, less than the size of pcap file 
    capture.apply_on_packets(window,packet_count=30000)
    capture.close()
    
    
    
    
    
