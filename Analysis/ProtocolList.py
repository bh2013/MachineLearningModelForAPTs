def protocolList(window):
    # ?normalises the protocol count data into percentages
    protocolCount = {}
    for packet in window:
        if packet["Protocol"] in protocolCount:
            protocolCount[packet["Protocol"]] += 1
        else:
            protocolCount[packet["Protocol"]] = 1
    
    for protocol in protocolCount:
        protocolCount[protocol] = protocolCount[protocol]/len(window)
    return protocolCount
        