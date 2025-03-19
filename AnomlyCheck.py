
import os
import numpy as np

import FormatData
import csv 
from datetime import datetime

avg = [
    67.50595000000001, 
    26.703089932796672, 
    60.0,
    557.1, 
    0.5,
    151.3428215772155,
    258.746614654137, 
    11.900819886503081,
    109.81692422601937,
    0.037329999999999995, 
    0.21427000000000002,
    0.0, 
    0.0,
    0.33503,
    0.0,
    0.3714799999999999, 
    0.00010000000000000002, 
    6.9, 
    
    
    
    0.0,
    0.09517681847869104, 
    0.09512284059179076, 
    0.09517704113379619, 
    0.00010838639949661485, 
    0.9048500591372065,
    0.0,
    0.0, 
    0.0, 
    0.004645752729244191,
    0.0, 
    0.0, 
    0.0, 
    0.0, 
    0.0, 
    0.0, 
    0.0, 
    0.0, 
    0.0, 
    0.0, 
    0.0, 
    0.0, 
    0.0, 
    0.0, 
    0.0, 
    0.0, 
    0.0, 
    0.0, 
    0.0, 
    0.0, 
    3350.3,
    0.0,
    3173.6,
    176.7, 
    1.0, 173.3, 
    1591.6, 
    0.0,
    0.0,
    176.7,
    0.0,
    0.0, 
    0.0, 
    0.0, 
    0.0, 
    0.0, 
    0.0, 
    0.007039456266824841,
    0.0189684, 
    0.0016832, 
    0.0029663617919325406
    ]

features = [
    # general stats
    "averagepacketlength",
    "deviationOfPacketLength",
    "minPacketLength",
    "MaxPacketLength",
    "outOfOrderPacketRatio",
    "packetRate",
    "windowTimeLength",
    "meanTimeBetweenPakets"
    "standardDeviationTimeBetweenPackets",
    "ARP",
    "DATA",
    "DNS",
    "ICMP",
    "MODBUS",
    "S7COMM",
    "TCP",
    "Unkown",
    "unkownIpCount",
    
    
    # TCP Flags
    "synAckattackFlag",
    "Fin Flag",
    "SYN Flag",
    "RST Flag",
    "PSH Flag",
    "Ack Flag",
    "URG Flag",
    "ECE Flag",
    "CWR Flag",
    
    # IMCP Stats
    "icmpReplyRateRatio",
    "icmpRedirectRatio",
    "icmpUnreachableRatio",
    "Type0",
    "Type3",
    "Type5",
    "Type8",
    "UnknownType",
    "icmpTTLAvg",
    "icmpFragmentationCheck",
    
    # Arp Stats
    "arpReplyRequestDiff",
    "arpSpoofFlag",
    
    # DNS Stats
    "dnsQueryRate",
    "DNSQueryRatePerSecond",
    
    # S7COMM Stats
    "plcCommCount",
    "PLcount",
    "ReadCount",
    "startCount",
    "stopCount",
    "writeCount",
    "ReadWriteRatio",
    
    # Modbus Stats
    "modbusCount",
    "ModbusCode1Count",
    "ModbusCode3Count",
    "ModbusCodeOtherCount",
    "ModbusReadWriteRatio",
    "ModbusRegister0",
    "ModbusRegister1",
    "ModbusRegister10",
    "ModbusRegister2",
    "ModbusRegister3",
    "ModbusRegister4",
    "ModbusRegister5",
    "ModbusRegister6",
    "ModbusRegister7",
    "ModbusRegister8",
    "ModbusRegister9",
    "ModbusRegisterOther",
    "ModbusAvgResponseTime",
    "ModbusMaxResponseTime",
    "ModbusMinResponseTime",
    "ModbusDeviationResponseTime"
]

anomalies = []

windowCountGlobal = 0

def check(window,windowCount):
    global windowCountGlobal
    windowCountGlobal = windowCount
    tidy = FormatData.Format(window)
    generalCheck(tidy[0])
    TCPCheck(tidy[1])
    ARPCheck(tidy[2])
    DNSCheck(tidy[3])
    ICMPCheck(tidy[4])
    s7CommCheck(tidy[5])
    modbusCheck(tidy[6])
    
    displayAnomalies()
    
    
# !-------S7COMM Check Functions-------!
# These functions check the S7COMM flags of the window
# These functions are called by the check function
# !-----------------------------------!

def s7CommCheck(s7CommInfo):
    plcCommCountCheck(s7CommInfo[0])
    s7functionCheck(s7CommInfo[1:4])
    ReadWriteRatioCheck(s7CommInfo[6])

def plcCommCountCheck(plcCommCount):
    if plcCommCount > 10:
        anomalies.append(("PLC Comm Count Suspiciously High, ", plcCommCount))

def s7functionCheck(s7function):
    for each in s7function:
        if each != 0:
            anomalies.append(("S7 Function, shoudlnt be runnig ", each))
            
def ReadWriteRatioCheck(ReadWriteRatio):
    print(ReadWriteRatio)
    
    
# !-------Modbus Check Functions-------!
# These functions check the Modbus flags of the window
# These functions are called by the check function
# !-----------------------------------!

def modbusCheck(modbusInfo):
    modbusCodeCountCheck(modbusInfo[1],modbusInfo[2],modbusInfo[3])
    
    ModbusReadWriteRatioCheck(modbusInfo[4])
    
    modbusRegisertCheck(modbusInfo[5:17])
    ModbusAvgResponseTimeCheck(modbusInfo[17:21])

def modbusCodeCountCheck(ModbusCode1, ModbusCode3, ModbusCodeOther):
    if ModbusCode1 > 0.2:
        anomalies.append(("Modbus Code 1 High, Possible Modbus Attack", ModbusCode1))
    if ModbusCode3 > 0.96:
        anomalies.append(("Modbus Code 3 High, Possible Modbus Attack", ModbusCode3))
    if ModbusCodeOther > 0.2:
        anomalies.append(("Modbus Code Other High, Possible Modbus Attack", ModbusCodeOther))
    
def ModbusReadWriteRatioCheck(ModbusReadWriteRatio):
    if ModbusReadWriteRatio > 0.15:
        anomalies.append(("Modbus Read Write Ratio Suspiciously High, Possible Modbus Attack", ModbusReadWriteRatio))
        
def modbusRegisertCheck(modbusRegister):
            
    if modbusRegister[0] > 0.4:
        anomalies.append(("Modbus Register 0 High, Possible Modbus Attack", modbusRegister[0]))

    if modbusRegister[1] > 0.95:
        anomalies.append(("Modbus Register 1 High, Possible flood on Register ", modbusRegister[1]))
    
    if modbusRegister[2] > 0.1:
        anomalies.append(("Modbus Register 10 High, Possible flood on Register ", modbusRegister[2]))
        
    if modbusRegister[3] > 0.4:
        anomalies.append(("Modbus Register 2 High, Possible flood on Register ", modbusRegister[3]))
    
    if modbusRegister[4] > 0.25:
        anomalies.append(("Modbus Register 3 High, Possible flood on Register ", modbusRegister[4]))

    if modbusRegister[5] > 0.1:
        anomalies.append(("Modbus Register 4High, Possible flood on Register ", modbusRegister[5])
    )
    if modbusRegister[6] > 0.1:
        anomalies.append(("Modbus Register 5 High, Possible flood on Register ", modbusRegister[6]))
    
    if modbusRegister[7] > 0.1:
        anomalies.append(("Modbus Register 6 High, Possible flood on Register ", modbusRegister[7]))
    
    if modbusRegister[8] > 0.1:
        anomalies.append(("Modbus Register 7 High, Possible flood on Register ", modbusRegister[8]))
        
    if modbusRegister[9] > 0.1:
        anomalies.append(("Modbus Register 8 High, Possible flood on Register ", modbusRegister[9]))
    
    if modbusRegister[10] > 0.1:
        anomalies.append(("Modbus Register 9 High, Possible flood on Register ", modbusRegister[10]))
    
    if modbusRegister[11] > 0.1:
        anomalies.append(("Modbus Register Unknown, Possible flood on Register ", modbusRegister[11]))
        
def ModbusAvgResponseTimeCheck(ModbusAvgResponseTime):
    if ModbusAvgResponseTime[0] != 0 and ModbusAvgResponseTime[1] != 0 and ModbusAvgResponseTime[2] != 0 and ModbusAvgResponseTime[3] != 0:
            
        if ModbusAvgResponseTime[0] > 0.1:
            anomalies.append(("Modbus Avg Response Time Suspiciously High, Possible Slow Drip", ModbusAvgResponseTime[0]))
        
        if ModbusAvgResponseTime[1] > 0.1:
            anomalies.append(("Modbus Max Response Time Suspiciously High, Possible Slow Drip", ModbusAvgResponseTime[1]))
        
        if ModbusAvgResponseTime[2] < 0.0001:
            anomalies.append(("Modbus Min Response Time Suspiciously Low, Possible DoS", ModbusAvgResponseTime[2]))

        if ModbusAvgResponseTime[3] > 0.01:
            anomalies.append(("Modbus Deviation Response Time Suspiciously High, Possible Slow Drip", ModbusAvgResponseTime[3]))
        
# !-------ARP Check Functions-------!
# These functions check the ARP flags of the window
# These functions are called by the check function
# !-----------------------------------!

def ARPCheck(arpInfo):
    arpReplyRequestDiffCheck(arpInfo[0])
    arpSpoofFlagCheck(arpInfo[1])

def arpReplyRequestDiffCheck(arpReplyRequestDiff):
    if arpReplyRequestDiff > 0.6:
        anomalies.append(("ARP Reply Request Diff Suspiciously High, Possible ARP Spoofing", arpReplyRequestDiff))


def arpSpoofFlagCheck(arpSpoofFlag):
    if arpSpoofFlag != 0:
        anomalies.append(("ARP Spoof Flag Detected, ARP Spoofing", arpSpoofFlag))
        
# !-------DNS Check Functions-------!
# These functions check the DNS flags of the window
# These functions are called by the check function
# !-----------------------------------!

def DNSCheck(dnsInfo):
    dnsQueryRateCheck(dnsInfo[0])
    DNSQueryRatePerSecondCheck(dnsInfo[1])

def dnsQueryRateCheck(dnsQueryRate):
    if dnsQueryRate > 0:
        if dnsQueryRate > 1.2:
            anomalies.append(("DNS Query Rate Suspiciously High, Possible DNS Tunneling", dnsQueryRate))
        if dnsQueryRate < 0.1:
            anomalies.append(("DNS Query Rate Suspiciously Low, Possible DoS", dnsQueryRate))

def DNSQueryRatePerSecondCheck(DNSQueryRatePerSecond):
    if DNSQueryRatePerSecond > 0.05:
        anomalies.append(("DNS Query Rate Per Second Suspiciously High, Possible DNS Tunneling", DNSQueryRatePerSecond))


# !-------ICMP Check Functions-------!
# These functions check the ICMP flags of the window
# These functions are called by the check function
# !-----------------------------------!
    
    
def ICMPCheck(icmpInfo):
    icmpReplyRateRatioCheck(icmpInfo[0])
    icmpRedirectRatioCheck(icmpInfo[1])
    icmpUnreachableRatioCheck(icmpInfo[2])
    icmpTypeCheck(icmpInfo[3], icmpInfo[4], icmpInfo[5], icmpInfo[6], icmpInfo[7])
    icmpTTLCheck(icmpInfo[8])
    icmpFragmentationCheck(icmpInfo[9])
    
def icmpReplyRateRatioCheck(icmpReplyRateRatio):
    if icmpReplyRateRatio > 0.05:
        anomalies.append(("ICMP Reply Rate Suspiciously High, Possible ICMP Flood", icmpReplyRateRatio))
    
def icmpRedirectRatioCheck(icmpRedirectRatio):
    if icmpRedirectRatio > 0.1:
        anomalies.append(("ICMP Redirect Ratio Suspiciously High, Possible ICMP Redirect Attack", icmpRedirectRatio))

def icmpUnreachableRatioCheck(icmpUnreachableRatio):
    if icmpUnreachableRatio > 0.05:
        anomalies.append(("ICMP Unreachable Ratio Suspiciously High, Possible ICMP Unreachable Flood", icmpUnreachableRatio))
    
def icmpTypeCheck(Type0, Type3, Type5, Type8, UnknownType):
    if Type0 > 0.2:
        anomalies.append(("ICMP Type 0  High, Possible ICMP Echo Flood", Type0))
    if Type3 < 0.8 or Type3 != 1:
        if Type3 != 0:
            anomalies.append(("ICMP Type 3, Possible ICMP Destination Unreachable Flood", Type3))
    if Type5 > 0.1:
        anomalies.append(("ICMP Type 5 High, Possible ICMP Redirect Flood", Type5))
    if Type8 > 0.2:
        anomalies.append(("ICMP Type 8 High, Possible ICMP Echo Reply Flood", Type8))
        
    if UnknownType >0:
        anomalies.append(("Unknown ICMP Type Detected", UnknownType))
              
def icmpTTLCheck(icmpTTLAvg):
    if icmpTTLAvg != 0:
        if icmpTTLAvg < 20 or icmpTTLAvg > 128:
            anomalies.append(("ICMP TTL Average Suspiciously High, Possible ICMP Flood", icmpTTLAvg))

def icmpFragmentationCheck(icmpFragmentation):
    if icmpFragmentation > 0.01:
        anomalies.append(("ICMP Fragmentation Suspiciously High, Possible ICMP Fragmentation Flood", icmpFragmentation))

# !-------TCP Check Functions-------!
# These functions check the TCP flags of the window
# These functions are called by the check function
# !-----------------------------------!

def TCPCheck(tcpInfo):
    synAckattackFlagCheck(tcpInfo[0])
    FlagCheck(tcpInfo[1], tcpInfo[2], tcpInfo[3], tcpInfo[4], tcpInfo[5], tcpInfo[6], tcpInfo[7], tcpInfo[8])

def synAckattackFlagCheck(synAckattackFlag):
    if synAckattackFlag != 0:
        anomalies.append(("SYN ACK Attack Flag Suspiciously High, Possible SYN ACK Attack", synAckattackFlag))
    
def FlagCheck(Fin, SYN, RST, PSH, Ack, URG, ECE, CWR):
    if Ack != 1:
        if Ack > 0.95 or Ack < 0.6:
            anomalies.append(("ACK Flag Suspicious, Possible ACK Attack", Ack))
            
            
    if Fin >0.2:
        anomalies.append(("FIN Flag Suspiciously High, FIN Scans", Fin))
    
    if SYN >0.5 and Ack < 0.3:
        anomalies.append(("SYN Flag Suspiciously High, Possible SYN Flood", SYN))  
        
    if URG > 0.01:
        anomalies.append(("Unkown Urg, should be 0, Possible URG Attack", URG))
        
    if ECE > 0.05:
        anomalies.append(("Unkown ECE, should be 0, Possible ECE conjestion", ECE))
        
    if CWR > 0.05:
        anomalies.append(("Unkown CWR, should be 0, Possible CWR conjestion", CWR))
        
    if RST > 0.5:
        anomalies.append(("RST Flag Ratio Suspiciously High, Possible RST Attack", RST))

    if PSH > 0.6:
        anomalies.append(("PSH Flag Suspiciously High, Possible PSH Flood", PSH))
        
    if Fin > 0.1 and PSH > 0.1 and URG >0.02:
        anomalies.append(("Suspicious Combination of Flags, Possible XMas Scan", 0))
    
    if Ack < 0.1 and SYN <0.1 and Fin < 0.1 and RST < 0.1 and PSH < 0.1 and URG < 0.1 and ECE < 0.1 and CWR < 0.1:
        anomalies.append(("Suspicious Combination of Flags, Possible NULL Scan", 0))
        
# !-------Genral Check Functions-------!
# These functions check the general stats of the window
# These functions are called by the check function
# !-----------------------------------!
    
def generalCheck(genralInfo):
    averageCheck(genralInfo[0])
    deviationCheck(genralInfo[1])
    minCheck(genralInfo[2])
    maxCheck(genralInfo[3])
    outOfOrderCheck(genralInfo[4])
    packetRateCheck(genralInfo[5])
    windowTimeCheck(genralInfo[6])
    meanTimeBetweenPaketsCheck(genralInfo[7])
    standardDeviationTimeBetweenPacketsCheck(genralInfo[8])
    protocolCheck(genralInfo[9],genralInfo[10],genralInfo[11],genralInfo[12],genralInfo[13],genralInfo[14],genralInfo[15],genralInfo[16])
    unkownIpCountCheck(genralInfo[17])    
    
def averageCheck(averagepacketlength):
    if averagepacketlength < 50:
        anomalies.append(("Average Packet Length Suspiciously Low", averagepacketlength))
    elif averagepacketlength > 1500:
        anomalies.append(("Average Packet Length Suspiciously High, Possible Anomaly", averagepacketlength))

def deviationCheck(deviationOfPacketLength):
    if deviationOfPacketLength > 80:
        anomalies.append(("Packet Length Deviation Suspiciously High, Possible DoS", deviationOfPacketLength))

def minCheck(minPacketLength):
    if minPacketLength < 20:
        anomalies.append(("Min Packet Length Suspiciously Low, Possible Slow Drip", minPacketLength))

def maxCheck(MaxPacketLength):
    if MaxPacketLength > 1500:
        anomalies.append(("Max Packet Length Suspiciously High, Possible Exfiltration", MaxPacketLength))

def outOfOrderCheck(outOfOrderPacketRatio):
    if outOfOrderPacketRatio > 10:
        anomalies.append(("Out of Order Packet Count Suspiciously High, Possible MITM or data exfiltarion", outOfOrderPacketRatio))

def packetRateCheck(packetRate):
    if packetRate < 0.045:
        anomalies.append(("Packet Rate Suspiciously Low, Possible DoS", packetRate))

def windowTimeCheck(windowTimeLength):
    # in mili seconds, will vary with lengths of windows, 510 for 10,000
    if windowTimeLength > 510:
        anomalies.append(("Window Time Length Suspiciously High, Possible Slow Drip", windowTimeLength))
    elif windowTimeLength < 0.01:
        anomalies.append(("Window Time Length Suspiciously Low, Possible DoS", windowTimeLength))

def meanTimeBetweenPaketsCheck(meanTimeBetweenPakets):
    if meanTimeBetweenPakets < 0.01:
        anomalies.append(("Mean Time Between Packets Suspiciously Low, Possible DoS", meanTimeBetweenPakets))

def standardDeviationTimeBetweenPacketsCheck(standardDeviationTimeBetweenPackets):

    if standardDeviationTimeBetweenPackets < 0.01:
        anomalies.append(("Standard Deviation Time Between Packets Suspiciously Low, Possible DoS", standardDeviationTimeBetweenPackets))

def protocolCheck(ARP, DATA, DNS, ICMP, MODBUS, S7COMM, TCP, Unkown):
    if ARP > 0.4:
        anomalies.append(("ARP Traffic Suspiciously High, Possible ARP Spoofing", ARP))
    if DATA > 0.5:
        anomalies.append(("DATA Traffic Suspiciously High, Possible Data Exfiltration", DATA))
    if DNS > 0.75:
        anomalies.append(("DNS Traffic Suspiciously High, Possible DNS Tunneling", DNS))
    if ICMP > 0.4:
        anomalies.append(("ICMP Traffic Suspiciously High, Possible DoS", ICMP))
    if MODBUS > 0.4:
        anomalies.append(("MODBUS Traffic Suspiciously High, Possible Modbus Attack", MODBUS))
    if S7COMM > 0.4:
        anomalies.append(("S7COMM Traffic Suspiciously High, Possible PLC Attack", S7COMM))
    if TCP > 0.75:
        anomalies.append(("TCP Traffic Suspiciously High, Possible TCP Attack", TCP))
    if Unkown > 0.2:
        anomalies.append(("Unkown Traffic Suspiciously High", Unkown))
        
def unkownIpCountCheck(unkownIpCount):
    if unkownIpCount > 10:
        anomalies.append(("Unknown IP Count Suspiciously High, Possible MITM", unkownIpCount))

# !-------Display Anomalies & exporting -------!

# Function to display all anomalies found in terminal for testing 
def displayAnomalies():
    global windowCountGlobal
    if anomalies:
        print(f"Detected Anomalies in window {windowCountGlobal}")
        for anomaly, value in anomalies:
            print(f"- {anomaly}: {value}")
            
        exportToCsv()
    else:
        print("No anomalies detected.")
    anomalies.clear()
    
    
def exportToCsv():
    global windowCountGlobal, anomalies
    fileName = "DataLogs/DataLog.csv"
    
    with open(fileName, mode='a') as file:
        writer = csv.writer(file)
        if file.tell() == 0:
            writer.writerow(["Timestamp", "Window", "Anomaly Description", "Value", "Possible Reason"])
            
        timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        
        for anomaly, value in anomalies:
            writer.writerow([timestamp, windowCountGlobal, anomaly, value])