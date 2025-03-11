def S7_Packet(packetInfo, pkt):
    try:
        packetInfo["Function"] = str(pkt.S7COMM.header_protid)
                

    except Exception as e:
        print("ErrorInS7Packet: " + str(e))
    return packetInfo
    
    
def JobRatio(window):
    for packet in window:
        if packet["Protocol"] == "S7COMM":
            pass
        
        
def S7StartProtocolCount(window):
    # readCount #0x01
    # writeCount #0x05
    # startCount #0x1B
    # stopCount #0x29
    # PLcount #0x32
    
    # PL count is the only used in this data set 
    
    functionList = {
        "ReadCount": 0,
        "writeCount": 0,
        "startCount": 0,
        "stopCount": 0,
        "PLcount": 0
    }

    for packet in window:
        if packet["Protocol"] == "S7COMM":
            if packet["Function"] == "0x01":
                functionList["ReadCount"] += 1
            elif packet["Function"] == "0x05":
                functionList["writeCount"] += 1
            elif packet["Function"] == "0x1B":
                functionList["startCount"] += 1
            elif packet["Function"] == "0x29":
                functionList["stopCount"] += 1
            elif packet["Function"] == "0x32":
                functionList["PLcount"] += 1
            else:
                if packet["Function"] not in function:
                    functionList[packet["Function"]] = 1
                else:
                    functionList[packet["Function"]] += 1

    
    removedNames = ["ReadCount","writeCount","startCount","stopCount","PLcount"]
    returnedList =[]
    for name in removedNames:
        returnedList.append(functionList[name])
        del functionList[name]

    print(returnedList)
    return returnedList