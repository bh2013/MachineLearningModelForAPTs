import tkinter as tk
from tkinter import ttk

from matplotlib import pyplot as plt

from matplotlib.backends.backend_tkagg import FigureCanvas
import numpy as np

def SegmentData(analysis,windowNumber):

    # averagePacketLength, deviationOfPacketLength, minMaxPacketLength, outOfOrderPacketRatio, flowStats, protocolList, unkownIps
    genral = analysis[0]
    # analysis of packet lengths
    averagePacketLength = genral[0]
    deviationOfPacketLength = genral[1]
    minLength = genral[2]
    maxLength = genral[3]
        
    # counts packets sequence and checks for out of order packets
    outOfOrderPacketRatio = genral[4]
    
    # Time based stats from the window 
    packetRate = genral[5]
    windowDuration = genral[6]
    meanTimeDifferencePerPacket = genral[7]
    deviationBetweenPacketsTime = genral[8]
    
    # list of percanges of protocols in the window
    arp = genral[9]
    data = genral[10]
    dns = genral[11]
    icmp = genral[12]
    modbus = genral[13]
    s7 = genral[14]
    tcp = genral[15]
    unkownProtocols = genral[16]
    
    # count of unkown IPs
    unkownIps = genral[17]
    
    
    packetLengthGraph(averagePacketLength,windowNumber)  
    packetRateGraph(packetRate,windowNumber)
    

    # tcpAnalysisSYNAttack, tcpAnalysisFlagDistrabution 
    tcp = analysis[1]
    # tcp = tcpGraph(tcp)
    
    #  arpReplyRequestDiff,arpSpoofFlag
    arp  = analysis[2]
    # arp = arpGraph(arp)
    
    
    
    # dnsQueryRate,DNSQueryRatePerSecond
    dns = analysis[3]
    # dns = dnsGraph(dns)
    
    

    # ICMPReplyRatio, RedirectRaio, UnreachableRatio, Typeratio, TTLAvg, FragmentationCheck
    icmp = analysis[4]
    # icmp = icmpGraph(icmp)
    
    
    # plcCommCount,s7functions
    s7 = analysis[5]
    # s7 = s7Graph(s7)s
    
    
    # modbusCount,functionDis,ratio,regCheck,modbusTimeStats
    modbus = analysis[6]
    # modbus = modbusGraph(modbus)


# Turn on interactive mode
plt.ion()

# Persistent storage for data points
graph_x = []  # This will store the window counts
graph_y = []  # This will store the average packet lengths

graph_x2 = []  # This will store the window counts
graph_y2 = []  # This will store the average packet lengths


# Create the figure and axes only once
fig, (ax1,ax2) = plt.subplots(2,1)
fig.tight_layout(pad=3.0)

ax1.set_xlabel('Window Count')
ax1.set_ylabel('Average Packet Length')
ax1.set_title('Average Packet Length Over Time')
ax1.set_ylim(50, 100)

ax2.set_xlabel('Window Count')
ax2.set_ylabel('Average Packet Rate')
ax2.set_title('Average Packet Rate Over Time')
ax2.set_ylim(0, 0.5)

# Create an empty line object (we will update its data later)
line, = ax1.plot([], [], marker='o', linestyle='-', label='Avg Packet Length')

line2, = ax2.plot([], [], marker='o', linestyle='-', label='Packet Rate')



def packetLengthGraph(avgPacketLength,count):
    # Append the new data
    graph_x.append(count)
    graph_y.append(avgPacketLength)
    line.set_data(graph_x, graph_y)
    ax1.relim()
    ax1.autoscale_view(True, True, True)
    fig.canvas.draw()
    fig.canvas.flush_events()
    fig.show()


def packetRateGraph(packetRate,count):
    # Append the new data
    graph_x2.append(count)
    graph_y2.append(packetRate)
    line2.set_data(graph_x2, graph_y2)
    ax2.relim()
    ax2.autoscale_view(True, True, True)
    fig.canvas.draw()
    fig.canvas.flush_events()
    fig.show()