def outOfOrderPacketCount(window):            
    total = sum(1 for i in range(1, len(window)) if window[i]["Packet No."] < window[i - 1]["Packet No."])
    return total


