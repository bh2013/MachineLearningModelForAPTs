import numpy as np 
import pandas as pd 
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt

# get the file 
data = pd.read_csv("SmallTrainingSet.csv")
print(data.head())
print(data.dtypes)


# isoForrest = IsolationForest()
# isoForrest.fit(data) 


# labels = isoForrest.predict(data)
# scores = isoForrest.score_samples(data)

# data['IF_Label'] = labels
# data['IF_Score'] = scores

# anomalies = data[data['IF_Label'] == -1]
# print("Number of anomalies detected:", len(anomalies))
# print(anomalies.head())

