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
    
    return (generalFormatted, tcpFormatted, arpFormatted, dnsFormatted, icmpFormatted, s7Formatted, modbusFormatted)
    
    
    
def formatData(data):
    formatedData = []
    for each in data:
        if type(each) == tuple:
            for item in each:
                formatedData.append(item)
        elif type(each) == dict:
            for key,value in each.items():
                formatedData.append((value))
        elif type(each) == set:
            for item in each:
                formatedData.append(item)
        else:
            formatedData.append(each)
            
    return (formatedData)

            

