#This file will act as a wireshark to run and read the data in real time 

# Pcap file with Industrial/scada rules https://www.netresec.com/?page=PCAP4SICS, 4SICS-GeekLounge-151022.pcap, 4SICS-GeekLounge-151021, 4SICS-GeekLounge-151020.pcap

# Libriaries 
import time
import psutil
import pyshark
import collections
# ---------------------z
# files to import 
import Analysis.General_Analysis as General_Analysis
import Analysis.getPacketInfo as getPacketInfo
import Analysis.TCP_Analysis as TCP_Analysis
import Analysis.ICMP_Analysis as ICMP_Analysis
import Analysis.ARP_Analysis as ARP_Analysis
import Analysis.DNS_Analysis as DNS_Analysis
import Analysis.S7_Analysis as S7_Analysis
import Analysis.Modbus_Analysis as Modbus_Analysis
import DataVisualisationb.GernalDataVisual as GernalDataVisual
import FormatData
import IsolationForrest
import AnomlyCheck


# ---------------------

# TODO - what needs to be analysed
# !Done
# ?General Stats with all packets
# ?1. Average Packet Length
# ?2. Deviation of Packet Length
# ?3. Out of Order Packet count
# ?6. Unkown Ip list
# ?7. Protocol List
# ?8. Min Max Packet Length

# ? Flow Stats
# ?9. total duration of window
# ?10. mean time difference between packets
# ?11. standard deviation between packets
# ?12. Entropy of the time between packets

# !Protocol specific stats
# ?TCP Stats
# ?1. SYN Attack Detection
# ?2. Flag Distribution
# ?3. Average Time between packets

#?DNS Stats 
#?1. DNS Query Rate per second
#?2. DNS Response Count
#?3. DNS Query Length

# ?ARP Stats
# ?1. ARP ReplyRequest Differnce
# ?2. ARP Spoof Flag
# ?3. Unkown IP Flag

# ?ICMP Stats
# ?1. Average Time to Live 
# ?2. ICMP Response Ratio
# ?3. ICMP Round Trip(request/Reply) averages
# ?4. ICMP Type Ratios
# ?5. ICMP Type checks (redirects, unreachable)
# ?6. ICMP Fragmentation Check

# ?S7COMM Stats
# ?1. PLC Communication Count
# ?2. S7 Start Protocol Count

# ?Modbus Stats
# ?1. Modbus Count
# ?2. Function Distribution
# ?3. Read/write Ratio
# ?4. Error Count
# ?5. Memory Register Checks
# ?6. Modbus Time Stats



count = 0 
def windowCount():
    global count
    count = count + 1
    return count
    

AllWindowsAnalysis = []


def getWindowsData(window):
    # sets first window to none
    prevWindow = None 
    def packetGet(pkt , window = window):
        global AllWindowsAnalysis
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
            # Take note of this 
            if count == 1:
                # !First Window, can't compare to previous
                analysis = analyseWindow(window)

                formatedData = FormatData.Format(analysis)
                AnomlyCheck.check(analysis,count)

                GernalDataVisual.SegmentData(formatedData,count)
                AllWindowsAnalysis.append(formatedData)
                print("\n Window " + str(count) + " Done " )
                prevWindow = window.copy()
                window.clear()
                return
            else:
                # otherwise both windows are wanting to be used for comparisons to be made
                
                analysis = analyseWindow(window)
                formatedData = FormatData.Format(analysis)
                AnomlyCheck.check(analysis,count)

                GernalDataVisual.SegmentData(formatedData,count)

                AllWindowsAnalysis.append(formatedData)
                
                print("Window " + str(count) + " Done \n" )

                prevWindow = window.copy()
            window.clear()
            
    return packetGet

def analyseWindow(window):
# checks if the window is the first window
    if not window:
        return None
        #Average packet length

    # !General Stats from window
    averagePacketLength = General_Analysis.windowAveragePacketLength(window)
    #Lists all protocols and returns them as perctages 
    protocolList = General_Analysis.protocolList(window)
    #Gets stats on the rates of packets, packets rate, window length, entropy of the window's packet intervals  
    flowStats = General_Analysis.packetRate(window)
    # ?gets the standard deviation of the packet length, not sure if usefull 
    deviationOfPacketLength = General_Analysis.windowDeviationPacketLength(window)
    outOfOrderPacketRatio = General_Analysis.outOfOrderPacketCount(window)
    minMaxPacketLength = General_Analysis.MinMaxLength(window)
    # checks for any unkown src or dst ips in the window
    unkownIps = General_Analysis.knownIpCheck(window)
    GeneralStats = averagePacketLength,deviationOfPacketLength,minMaxPacketLength,outOfOrderPacketRatio,flowStats,protocolList,unkownIps
    
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
    ICMPAnalysis = ICMPReplyRatio, RedirectRaio, UnreachableRatio, Typeratio, TTLAvg, FragmentationCheck


    # !ARP Analysis of window
    arpReplyRequestDiff = ARP_Analysis.ReplyRequestDiffernce(window)
    arpSpoofFlag = ARP_Analysis.DetectARPSpoof(window)
    ARPAnalysis = arpReplyRequestDiff,arpSpoofFlag

    
    # !DNS Analysis of window
    dnsQueryRate = DNS_Analysis.DNSQueryRatePerSecond(window)
    DNSQueryRatePerSecond = DNS_Analysis.DNSResponse(window)
    DNSAnalysis = dnsQueryRate,DNSQueryRatePerSecond

    
    # !S7COMM Analysis of window
    plcCommCount = S7_Analysis.plcCommCount(window)
    s7functions = S7_Analysis.S7StartProtocolCount(window) 
    S7Anlysis = plcCommCount,s7functions

    
    # !Modbus Analysis of window
    modbusCount = Modbus_Analysis.modbusCounter(window)
    functionDis = Modbus_Analysis.codeDistribution(window)
    ratio = Modbus_Analysis.readWriteRatio(window)
    regCheck = Modbus_Analysis.memoryRegisterChecks(window)
    modbusTimeStats = Modbus_Analysis.TimeChecks(window)
    ModbusAnalysis = modbusCount,functionDis,ratio,regCheck,modbusTimeStats

    
    # !Return all the variables
    
    # printSHape of each variable
    def count_items(item):
        if isinstance(item, (int, float)):
                return 1
        elif isinstance(item, (list, tuple, set)):
            return sum(count_items(sub) for sub in item)
        elif isinstance(item, dict):
            return sum(count_items(val) for val in item.values())
        else:
            return 0

    # print("GeneralStats count:", count_items(GeneralStats))
    # print("TCPAnalysis count:", count_items(tcpAnalysis))
    # print("ARPAnalysis count:", count_items(ARPAnalysis))
    # print("DNSAnalysis count:", count_items(DNSAnalysis))
    # print("ICMPAnalysis count:", count_items(ICMPAnalysis))
    # print("S7Analysis count:", count_items(S7Anlysis))
    # print("ModbusAnalysis count:", count_items(ModbusAnalysis))
    
    # total = count_items(GeneralStats) + count_items(tcpAnalysis) + count_items(ARPAnalysis) + count_items(DNSAnalysis) + count_items(ICMPAnalysis) + count_items(S7Anlysis) + count_items(ModbusAnalysis)
    # print("Total count:", total)

    return GeneralStats,tcpAnalysis,ARPAnalysis,DNSAnalysis,ICMPAnalysis,S7Anlysis,ModbusAnalysis


# main function
if __name__ == "__main__":
# ?Can be changed to just capture on an interface, but for now just using a file
    maxWindow = 1000
    windowDataInfo = collections.deque(maxlen=maxWindow)
    window = getWindowsData(windowDataInfo)
    # ?Clean Data
    capture = pyshark.FileCapture("FileData/clean-6h.pcap")
    # capture = pyshark.FileCapture("FileData/4SICS-G
    # eekLounge-151022.pcap")
    
    # !Dirty Data 
    # capture = pyshark.FileCapture("FileData/mitm-change-1m-6h_1.pcap")
    # capture = pyshark.FileCapture("FileData/modbusFlood5m-30.pcap")
    # capture = pyshark.FileCapture("FileData/pingFloodDDoS1-1h.pcap")
    # capture = pyshark.FileCapture("FileData/MITM1m-30.pcap")
    # capture = pyshark.FileCapture("FileData/tcpSYNFlood-30m.pcap")
    # capture = pyshark.FileCapture("FileData/Flood1-30.pcap") 
    
    capture.apply_on_packets(window,packet_count=100000)
    capture.close()
        
    
    # !Training Model on clean data
    clean = AllWindowsAnalysis
    
    cleanAverage = IsolationForrest.averageOfWindow(clean)
    
    
    IsolationForrest.trainModel(clean)

    AllWindowsAnalysis = []
    # # !Dirty
    # capture2 = pyshark.FileCapture("FileData/mitm-change-1m-6h_1.pcap")
    # capture2 = pyshark.FileCapture("FileData/modbusFlood5m-30.pcap")

    # capture2.apply_on_packets(window,packet_count=20000)
    # capture2.close()
    
    dirty = AllWindowsAnalysis
    IsolationForrest.isoFor(dirty)


    

    
    

    
