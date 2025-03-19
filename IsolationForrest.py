
import numpy as np 
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import shap
import os 
import pickle
# get the file 

def averageOfWindow(analysis):
    # !segments data for each protocol 
    protocolsCount = len(analysis[0])
    totalsFinal = []
    for each in range(protocolsCount):
        data = [window[each] for window in analysis]
        totals = [sum(values) for values in zip(*data)] 
        totalsFinal.append(totals)

    averageTotal = []
    for each in totalsFinal:
        for i in each:
            averageTotal.append(i/len(analysis))
            
    return averageTotal


# averagepacketlength,deviationOfPacketLength,minPacketLength,MaxPacketLength,outOfOrderPacketRatio,packetPerSecond,windowTiemLength,protocolList(7, each protocol, one being unkown),unkownIpCount
# synAckattackFlag, 
# icmpReplyRateRatio, icmpRedirectRatio, icmpUnreachableRatio, icmpTypeRatio, icmpTTLAvg, icmpFragmentationCheck
# arpReplyRequestDiff, arpSpoofFlag,
# dnsQueryRate, DNSQueryRatePerSecond
# plcCommCount, s7functions("ReadCount": 0, "writeCount": 0,"startCount": 0, "stopCount": 0, "PLcount": 0)

# modbusCount, functionDis(3 outputs counts of functions 0,1,3), ratio, regCheck(11 outputs, counts of each regiser), modbusTimeStats(4 outputs,response time,max time, min time, devation of time)
 
# General Stats (7 features)
# TCP Flags (9 features)
# ICMP Stats (2 features)
# ARP Anomalies (2 features)
# DNS Query Rate (5 features)
# S7comm Industrial (7 features)
# Modbus Industrial (7 features)


features = [
    # general stats
    "averagepacketlength",
    "deviationOfPacketLength",
    "minPacketLength",
    "MaxPacketLength",
    "outOfOrderPacketCount",
    "packetRate",
    "windowTimeLength",
    "meanTimeBetweenPakets"
    "standardDeviationTimeBetweenPackets",
    "ARP",
    "DATA",
    "DNS",
    "ICMP",
    "MODBUS",
    "S7COMM",
    "TCP",
    "Unkown",
    "unkownIpCount",
    
    
    # TCP Flags
    "synAckattackFlag",
    "Fin Flag",
    "SYN Flag",
    "RST Flag",
    "PSH Flag",
    "Ack Flag",
    "URG Flag",
    "ECE Flag",
    "CWR Flag",
    
    # IMCP Stats
    "icmpReplyRateRatio",
    "icmpRedirectRatio",
    "icmpUnreachableRatio",
    "Type0",
    "Type3",
    "Type5",
    "Type8",
    "UnknownType",
    "icmpTTLAvg",
    "icmpFragmentationCheck",
    
    # Arp Stats
    "arpReplyRequestDiff",
    "arpSpoofFlag",
    
    # DNS Stats
    "dnsQueryRate",
    "DNSQueryRatePerSecond",
    
    # S7COMM Stats
    "plcCommCount",
    "PLcount",
    "ReadCount",
    "startCount",
    "stopCount",
    "writeCount",
    "ReadWriteRatio",
    
    # Modbus Stats
    "modbusCount",
    "ModbusCode1Count",
    "ModbusCode3Count",
    "ModbusCodeOtherCount",
    "ModbusReadWriteRatio",
    "ModbusRegister0",
    "ModbusRegister1",
    "ModbusRegister10",
    "ModbusRegister2",
    "ModbusRegister3",
    "ModbusRegister4",
    "ModbusRegister5",
    "ModbusRegister6",
    "ModbusRegister7",
    "ModbusRegister8",
    "ModbusRegister9",
    "ModbusRegisterOther",

    "ModbusRegisterOther",
    
    "ModbusAvgResponseTime",
    "ModbusMaxResponseTime",
    "ModbusMinResponseTime",
    "ModbusDeviationResponseTime"
]


def trainModel(clean,modeFile = "model/IsolationForest.pkl", scalerFile = "model/scaler.pkl"):
    
    print("Training Isolation Forest model...")
    
    os.makedirs("model", exist_ok=True) 
    
    cleanFormatted= combineData(clean)
    cleanArr = np.array(cleanFormatted)

    scaler = StandardScaler()
    trainCleanScaled = scaler.fit_transform(cleanArr)
    isoForest = IsolationForest(n_estimators=500, contamination=0.1, max_samples="auto", random_state=42, warm_start=True)
    isoForest.fit(trainCleanScaled)
    
    
    predictions = isoForest.predict(trainCleanScaled)
    scores = isoForest.decision_function(trainCleanScaled)

    print("\nIsolationForest Predictions & Scores:\n")
    for i, score in enumerate(scores):
        label = "Anomaly" if predictions[i] == -1 else "Normal"
        print(f"Window {i}: Score = {score:.4f} → {label}")
        
    
    with open(modeFile, "wb") as file:
        pickle.dump(isoForest, file)
    
    with open(scalerFile, "wb") as file:
        pickle.dump(scaler, file)
        
    print("Model trained and saved.")
    
    return isoForest, scaler


def loadModel(modelFile = "model/IsolationForest.pkl", scalerFile = "model/scaler.pkl"):
    
    try:
        with open(modelFile, "rb") as file:
            isoForest = pickle.load(file)
            
        with open(scalerFile, "rb") as file:
            scaler = pickle.load(file)
            
        return isoForest, scaler
    
    except FileNotFoundError:
        print("Model not found. Please train the model first.")
        return None, None

def isoFor(dirty):
    
    isoForest, scaler = loadModel()
    
    
    dirtyNew = combineData(dirty)
    dirtyArray = np.array(dirtyNew)
    trainDirtyScaled = scaler.transform(dirtyArray)
    

    predictions = isoForest.predict(trainDirtyScaled)
    scores = isoForest.decision_function(trainDirtyScaled)

    # predictions = isoForest.predict(trainCleanScaled)
    # scores = isoForest.decision_function(trainCleanScaled)
    

    print(predictions)
    
    print("\nIsolationForest Predictions & Scores:\n")
    for i, score in enumerate(scores):
        label = "Anomaly" if predictions[i] == -1 else "Normal"
        print(f"Window {i}: Score = {score:.4f} → {label}")
        
        
    # !explain clean data
    # explainer = shap.Explainer(isoForest,trainCleanScaled)
    # shapVals = explainer(trainCleanScaled)
    
    
    
    # shap.summary_plot(shapVals, pd.DataFrame(trainCleanScaled, columns= features))
    

    
    # anomalyIndices = np.where(predictions == -1)[0]
    
    # if len(anomalyIndices) > 0:
    #     idx = anomalyIndices[0]
    #     print(f"\nSHAP explanation for the first anomaly (Window {idx}):\n")
    #     displayShap(shapVals[idx], cleanArray[idx])
    # else:
    #     print("\nNo anomalies detected.")
        
        
        
        
    # # !explain dirty data
    # explainer = shap.Explainer(isoForest,trainDirtyScaled)
    # shapVals = explainer(trainDirtyScaled)
    
    
    
    # shap.summary_plot(shapVals, pd.DataFrame(trainDirtyScaled, columns= features))
    

    
    # anomalyIndices = np.where(predictions == -1)[0]
    
    # if len(anomalyIndices) > 0:
    #     idx = anomalyIndices[0]
    #     print(f"\nSHAP explanation for the first anomaly (Window {idx}):\n")
    #     displayShap(shapVals[idx], trainDirtyScaled[idx])
    # else:
    #     print("\nNo anomalies detected.")



def displayShap(shapVals, data):
    
    shapArr = shapVals.values
    baseValue = shapVals.base_values
    prediction = baseValue + shapArr.sum()
    
    print(f"Base Value: {baseValue:.4f}")
    print(f"Prediction: {prediction:.4f}")
    
    
    print(f"{'Feature #':<12} {'Feature Value':<15} {'SHAP Value':<12} {'Impact'}")

    
    for idx, val in enumerate(shapArr):
        impact = "↑ Anomaly" if val < 0 else "↓ Normal"
        if impact == "↑ Anomaly":
            print(f"{idx:<12} {data[idx]:<15.4f} {val:<12.4f} {impact}")
        
        
    # Simple terminal SHAP display:

    # anomaly_scores = iso_forest.decision_function(trainScaled)

    # predictions = iso_forest.predict(trainScaled)
    # print(predictions)
    
    
    # # Print the scores
    # for i, score in enumerate(anomaly_scores):
    #     print(f"Window {i}: Anomaly Score = {score}")


def combineData(allWindows):
    oneList = []
    for window in allWindows:
        returnList = []
        for protocol in window:
            for value in protocol:
                returnList.append(value)
        oneList.append(returnList)
    return oneList




# labels = isoForrest.predict(data)
# scores = isoForrest.score_samples(data)

# data['IF_Label'] = labels
# data['IF_Score'] = scores

# anomalies = data[data['IF_Label'] == -1]
# print("Number of anomalies detected:", len(anomalies))
# print(anomalies.head())

