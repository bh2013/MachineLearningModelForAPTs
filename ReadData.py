#This file will act as a wireshark to run and read the data in real time 

# Pcap file with Industrial/scada rules https://www.netresec.com/?page=PCAP4SICS, 4SICS-GeekLounge-151022.pcap, 4SICS-GeekLounge-151021, 4SICS-GeekLounge-151020.pcap

# Libriaries 
import time
import psutil
import pyshark
import collections
# ---------------------z
# files to import 
from Analysis import AveragePacketLength, DeviationOfPacketLength, FlowStats, IpCheck, OutOfOrderPackets, ProtocolList
import Analysis.getPacketInfo as getPacketInfo
import Analysis.TCP_Analysis as TCP_Analysis
import Analysis.ICMP_Analysis as ICMP_Analysis
import Analysis.ARP_Analysis as ARP_Analysis
import Analysis.DNS_Analysis as DNS_Analysis
# ---------------------

# TODO - what needs to be analysed
# !Done
# ?General Stats with all packets
# ?1. Average Packet Length
# ?2. Deviation of Packet Length
# ?3. Out of Order Packet count
# ?5. packetRate

# ? Flow Stats
# ?6. total duration of window
# ?7. mean time difference between packets
# ?8. standard deviation between packets
# ?10. Entropy of the time between packets

# ?Protocol Specific
# ?11. 1 or 0 if SYN attack w/ TCP
# ?12. Protocol List w/ ratios 
# ?13. Flag distrabution of TCP packets
# ?14. Known IP check, 0 if all known, count how many unkown ips

#TODO - what needs to be added
#?Gernal Stats needing recorded

#?DNS Stats 
#?1. DNS Query Rate
#?2. DNS Response Rate
#?3. DNS Query Length
#?4. DNS Response Length

# ?ARP Stats
# ?1. ARP Response

# ?ICMP Stats
# ?1. ICMP ratio, high is suspicius

#?Data in out tracker, any data in or out of the network
#?1. Data in Rate
#?2. Data out Rate

# ?ICS Protocols
#?Modbus, S7COMM, 



# 4.Retransmission Rate	
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
        
        
        
        # !Size based window
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
                analysis = analyseWindow(window)
                print(analysis)
                prevWindow = window.copy()
                window.clear()
                return
            else:
                # otherwise both windows are wanting to be used for comparisons to be made 
                analysis = analyseWindow(window)
                print(analysis)
                prevWindow = window.copy()
            window.clear()
            
        
            
    return packetGet

def analyseWindow(window):
# checks if the window is the first window
    if not window:
        return None
        #Average packet length
    
    # !General Stats from window
    averagePacketLength = AveragePacketLength.windowAveragePacketLength(window)
    #Lists all protocols and returns them as perctages 
    protocolList = ProtocolList.protocolList(window)
    #Gets stats on the rates of packets, packets rate, window length, entropy of the window's packet intervals  
    flowStats = FlowStats.packetRate(window)
    # ?gets the standard deviation of the packet length, not sure if usefull 
    deviationOfPacketLength = DeviationOfPacketLength.windowDeviationPacketLength(window)
    
    outOfOrderPacketRatio = OutOfOrderPackets.outOfOrderPacketCount(window)
    # checks for any unkown src or dst ips in the window
    unkownIps = IpCheck.knownIpCheck(window)
    
    GeneralStats = averagePacketLength,deviationOfPacketLength,outOfOrderPacketRatio,flowStats,protocolList,unkownIps
    
    # !TCP Analysis of window 
    # if the packet is tcp then check its flags, and replies, if tcpAnalysisSYNAttack is 1 then its a SYN attack
    tcpAnalysisSYNAttack,tcpAnalysisFlagDistrabution = TCP_Analysis.ackReplyCheck(window)
    
    tcpAnalysis =  tcpAnalysisSYNAttack,tcpAnalysisFlagDistrabution 
    
    # !ICMP Analysis of window
    ICMPReplyRatio = ICMP_Analysis.ResponseRatio(window)
    Typeratio = ICMP_Analysis.typeRatios(window)
    TTLAvg = ICMP_Analysis.TTLAvg(window)
    FragmentationCheck = ICMP_Analysis.fragmentationCheck(window)
    RedirectRaio,UnreachableRatio = ICMP_Analysis.TypeChecks(window)    
    # ICMPRoundTripAnalysis = ICMP_Analysis.RoundTrips(window) - no round trips in data set, always 0 

    ICMPAnalysis = ICMPReplyRatio,RedirectRaio,UnreachableRatio, Typeratio, TTLAvg, FragmentationCheck
    
    
    # !ARP Analysis of window
    arpReplyRequestDiff = ARP_Analysis.ReplyRequestDiffernce(window)
    arpSpoofFlag = ARP_Analysis.DetectARPSpoof(window)
    
    ARPAnalysis = arpReplyRequestDiff,arpSpoofFlag
    
    
    # !DNS Analysis of window
    dnsQueryRate = DNS_Analysis.DNSQueryRatePerSecond(window)
    DNSQueryRatePerSecond = DNS_Analysis.DNSResponse(window)

    DNSAnalysis = dnsQueryRate,DNSQueryRatePerSecond
    
    # !S7COMM Analysis of window
    suspiciousActivityFlag = 0
    
    
    # !Modbus Analysis of window
    modbusActivityFlag = 0
    
    # !Return all the variables
    
    
    # return GeneralStats,tcpAnalysis,ICMPAnalysis,ARPAnalysis
    return GeneralStats,tcpAnalysis,DNSAnalysis,ARPAnalysis,ICMPAnalysis
    
def timeBasedWindowAnalysis(pkt):
    window = collections.deque()
    packet = getPacketInfo.get(pkt)
    
    window.append(packet)    
        
    
   
# main function
if __name__ == "__main__":
# ?Can be changed to just capture on an interface, but for now just using a file
    maxWindow = 5000
    windowDataInfo = collections.deque(maxlen=maxWindow)    
    capture = pyshark.FileCapture("FileData/4SICS-GeekLounge-151022.pcap")
    window = getWindowsData(windowDataInfo)
    # !set to 0 to make constant or just choose a big number, less than the size of pcap file 
    capture.apply_on_packets(window,packet_count=100000)
    capture.close()
 
    # windowDataInfo = collections.deque()    
    # capture = pyshark.FileCapture("FileData/4SICS-GeekLounge-151020.pcap")
    # capture.apply_on_packets(timeBasedWindowAnalysis)
    
    

    
    