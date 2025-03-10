import  numpy as np 

def packetRate(window):
    if not window:
        return 0,0,0,0
    
    startTime = float(window[0]["Time"])

    if len(window) == 1:
        return 1
    
    endTime = float(window[-1]["Time"])
    
    durationOfWidnow = endTime - startTime
    
    # calculting average packet time for window, and standard deviation between packets
    times = [float(packet["Time"]) for packet in window]
    
    # calcuates the time between packets 
    diffInTimeBetweenPackets = np.diff(times) if len(times) > 1 else [1]
    
    meanTimeDifferencePerPacket = np.mean(diffInTimeBetweenPackets)
    standardDeviationBetweenPackets = np.std(diffInTimeBetweenPackets)
    
    # # calculate entrop of the time between packets
    historgram, bin_edge = np.histogram(diffInTimeBetweenPackets, bins = 10, density=True)
    historgram = historgram/np.sum(historgram)
    historgram = historgram[historgram >0]
    entropy = -np.sum(historgram * np.log2(historgram))
    
  
    
    
    # better algorothm for entropy
    # https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.entropy.html
    
    if durationOfWidnow == 0:
        return len(window)
    
    packetRate = len(window)/durationOfWidnow
    
    
    return {
        float(packetRate),
        float(durationOfWidnow),
        float(meanTimeDifferencePerPacket),
        float(standardDeviationBetweenPackets),
        # float(entropy(np.histogram(diffInTimeBetweenPackets, bins=10, density=True)[0]))  # Better entropy calc
        }