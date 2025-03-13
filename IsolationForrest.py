import numpy as np 
import pandas as pd 
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt

# get the file 


def displayData(analysis):
    # !segments data for each protocol 
    genral = analysis[0]
    tcp = analysis[1]
    arp  = analysis[2]
    dns = analysis[3]
    icmp = analysis[4]
    s7 = analysis[5]
    modbus = analysis[6]
    print((genral)) 


# isoForrest = IsolationForest()
# isoForrest.fit(data) 


# labels = isoForrest.predict(data)
# scores = isoForrest.score_samples(data)

# data['IF_Label'] = labels
# data['IF_Score'] = scores

# anomalies = data[data['IF_Label'] == -1]
# print("Number of anomalies detected:", len(anomalies))
# print(anomalies.head())

