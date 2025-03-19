import numpy as np

def Modbus_Packet(packetInfo, pkt):
    try:
        packetInfo["Function"] = pkt.modbus.func_code
        # for each in pkt.modbus.response_time: print(each)
        if "response_time" in dir(pkt.modbus):
            packetInfo["ModbusTime"] = float(pkt.modbus.response_time)
        # packetInfo["ModbusTime"] = pkt.modbus.response_time
        
        if "regval_uint16" in dir(pkt.modbus):
            regList = []
            reg = pkt.modbus.regval_uint16
            if len(reg) > 1:
                for each in reg:
                    regList.append(each)
                packetInfo["Registers"] = regList
            else:
                packetInfo["Registers"] = reg

    except Exception as e:
        print("ErrorInModbusPacket: " + str(e))
    return packetInfo

def modbusCounter(window):
    total = sum(1 for packet in window if packet["Protocol"] == "MODBUS")
    return total


def codeDistribution(window):
    functionCodes = {
        "1": 0,
        "3": 0,        
        "Other": 0
    }
    for packet in window:
        if packet["Protocol"] == "MODBUS":
            if packet["Function"] not in functionCodes:
                functionCodes["Other"] += 1 
            else:
                functionCodes[str(packet["Function"])] += 1
                
    sortedCodes = {k: functionCodes[k] for k in sorted(functionCodes)}
    return sortedCodes



def readWriteRatio(window):
    readCount = 0
    writeCount = 0
    
    for packet in window:
        if packet["Protocol"] == "MODBUS":
            if packet["Function"] == "3":
                readCount += 1
            elif packet["Function"] == "6":
                writeCount += 1

    if readCount == 0 or writeCount == 0:
        return 0
    else:
        print(readCount, writeCount)
        
        return (writeCount/writeCount )
    

def errorCount(window):
    errorCount = 0
    for packet in window:
        if packet["Protocol"] == "MODBUS":
            if packet["Function"] == "5":
                errorCount += 1
    if errorCount == 0:
        return 0
    else:
        return errorCount


def memoryRegisterChecks(window):
    register = {
        "0": 0,
        "1": 0, 
        "2": 0,
        "3": 0,
        "4": 0,
        "5": 0,
        "6": 0,
        "7": 0,
        "8": 0,
        "9": 0,
        "10": 0,
        "Other": 0
    }
    for packet in window:
        if packet["Protocol"] == "MODBUS":
            if "Registers" in packet:
                if len(packet["Registers"]) > 1:
                    for each in packet["Registers"]:
                        if each in register:
                            register[each] += 1 
                        else:
                            register[each] = 0 
                else:
                        if packet["Registers"] in register:
                            register[packet["Registers"]] += 1 
                        else:
                            register["Other"] += 1

    sortedReg = {k: register[k] for k in sorted(register)}
        
    return sortedReg
                
def TimeChecks(window):
    modbusTimes = []
    for packet in window:
        if packet["Protocol"] == "MODBUS" and "ModbusTime" in packet:
            modbusTimes.append(packet["ModbusTime"])
            
    if len(modbusTimes) == 0:
        return 0,0,0,0
    
    averageresponseTime = np.mean(modbusTimes)
    maxTime = np.max(modbusTimes)
    minTime = np.min(modbusTimes)
    stdDev = np.std(modbusTimes)
    
    return float(averageresponseTime), float(maxTime), float(minTime), float(stdDev)
    
            
    

