def S7_Packet(packetInfo, pkt):
    try:
        packetInfo["Function"] = str(pkt.S7COMM.header_protid)

        packetInfo["Destination"] = pkt.ip.dst
        

        
    except Exception as e:
        print("ErrorInS7Packet: " + str(e))
    return packetInfo
    
# !Counts the number of unique destination IPs in the window, used to check for multiple PLCs, if sudden spike or gradual should notice its not noral that theres a new ip 
def plcCommCount(window):
    destinationList = []
    for packet in window:
        if packet["Protocol"] == "S7COMM":
            if packet["Destination"] not in destinationList:
                destinationList.append(packet["Destination"])

    return len(destinationList)

# !Checks the counts of the different S7 functions in the window
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


    if functionList["ReadCount"] == 0 or functionList["writeCount"] == 0:
        readWriteRatio = 0
    else:
        readWriteRatio = packet["ReadCount"] / packet["writeCount"]
    

    removedNames = ["ReadCount","writeCount","startCount","stopCount","PLcount"]
    returnedList =[]
    for name in removedNames:
        returnedList.append(functionList[name])
        del functionList[name]


    return returnedList,readWriteRatio
