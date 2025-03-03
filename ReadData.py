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
# 1. Handle differnt types of protocols
# 2. Implement ackReplyCheck


# dealing with differnt protocols, all pakcets gett added to the window, then the window is analysed

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
        average = getPacketInfo.windowAveragePacketLength(window)
        protocolList = getPacketInfo.protocolList(window)
        packetRate = getPacketInfo.packetRate(window)
        deviation = getPacketInfo.windowDeviationPacketLength(window)
        AckReplyCheck = getPacketInfo.ackReplyCheck(window)
        return average,protocolList,packetRate,deviation,AckReplyCheck
    else:    
        average = getPacketInfo.windowAveragePacketLength(window)
        protocolList = getPacketInfo.protocolList(window)
        packetRate = getPacketInfo.packetRate(window)
        deviation = getPacketInfo.windowDeviationPacketLength(window)
        AckReplyCheck = getPacketInfo.ackReplyCheck(window)
        
        return average,protocolList,packetRate,deviation,AckReplyCheck
        
# main function
if __name__ == "__main__":
# ?Can be changed to just capture on an interface, but for now just using a file
    maxWindow = 5000
    windowDataInfo = collections.deque(maxlen=maxWindow)
    capture = pyshark.FileCapture("FileData/4SICS-GeekLounge-151022.pcap")
    window = getWindowsData(windowDataInfo)
    # !set to 0 to make constant
    capture.apply_on_packets(window,packet_count=300000)
    capture.close()
    
    
    
    
    
