def get(pkt):
    # Get the packet info 
    # (pkt.frame_info)- for general info: packet time, interface name etc
    # set all usefull info into a dictionary
    packetInfo = {}
    try: 
        packetInfo["Packet No."] = pkt.number
        packetInfo["Protocol"] = pkt.highest_layer
        packetInfo["Source"] = pkt.ip.src
        packetInfo["Destination"] = pkt.ip.dst
        packetInfo["Time"] = pkt.frame_info.time_epoch
        packetInfo["Length"] = pkt.length
        return packetInfo
    
    except Exception as e:
        print("ErrorInPacketInfo: " + str(e))
        return packetInfo
    # time stamp for packet
    # epochTime = pkt.frame_info.time_epoch
    # print("Epoch Time: " + str(epochTime))

    # layers = pkt.layers
    # ETH = layers[0] - Link layer 
    # IP = layers[1] - Network layer
    # ... etc
    # for layer in layers:
    #     print(layer)
    