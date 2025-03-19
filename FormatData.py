def Format(dataset):
    general = dataset[0]
    tcp = dataset[1]
    arp = dataset[2]
    dns = dataset[3]
    icmp = dataset[4]
    s7 = dataset[5]
    modbus = dataset[6]
    
    generalFormatted = formatData(general)
    tcpFormatted = formatData(tcp)
    arpFormatted = formatData(arp)
    dnsFormatted = formatData(dns)
    icmpFormatted = formatData(icmp)
    s7Formatted = formatData(s7)
    modbusFormatted = formatData(modbus)
    
    generalLen = len(generalFormatted)
    tcpLen = len(tcpFormatted)
    arpLen = len(arpFormatted)
    dnsLen = len(dnsFormatted)
    icmpLen = len(icmpFormatted)
    s7Len = len(s7Formatted)
    modbusLen = len(modbusFormatted)

    count = generalLen + tcpLen + arpLen + dnsLen + icmpLen + s7Len + modbusLen
    return (generalFormatted, tcpFormatted, arpFormatted, dnsFormatted, icmpFormatted, s7Formatted, modbusFormatted)
    
    
def formatData(data):
    formatedData = []
    for each in data:

        if type(each) == tuple:
            for item in each:
                if type(item) == tuple or type(item) == list:
                    for i in item:
                        formatedData.append(i)
                else:
                    formatedData.append(item)
        elif type(each) == dict:
            for key,value in each.items():
                formatedData.append((value))
        elif type(each) == set:
            for item in each:
                formatedData.append(item)
        elif type(each) == list:
            for item in each:
                formatedData.append(item)
        else:
            formatedData.append(each)
            
            
    
    return (formatedData)

            

