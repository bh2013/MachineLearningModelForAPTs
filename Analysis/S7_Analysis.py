def S7_Packet(packetInfo, pkt):
    try:
        packetInfo["Function"] = pkt.S7COMM.header_protid
        
        print(str(pkt.S7COMM.header_protid))
        
        
        if hex(packetInfo["Function"]) == hex(0x32):
            print("yippee")
        
    except Exception as e:
        print("ErrorInS7Packet: " + str(e))
    return packetInfo
    
    
def JobRatio(window):
    for packet in window:
        if packet["Protocol"] == "S7COMM":
            pass
        
        
def S7StartProtocolCount(window):
    pass