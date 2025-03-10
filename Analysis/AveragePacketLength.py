def windowAveragePacketLength(window):  
    average = sum(int(packet["Length"]) for packet in window)/len(window)
    return float(average)
