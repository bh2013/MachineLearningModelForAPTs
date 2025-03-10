import numpy as np

# def windowDeviationPacketLength(window):
#     # ?Uses Welford's algorithm to calc standard deviation
#     n = 0
#     mean = 0.0
#     M2 = 0.0
#     for packet in window:
#         x = float(packet["Length"])
#         n += 1
#         delta = x - mean
#         mean += delta / n
#         delta2 = x - mean
#         M2 += delta * delta2
#     if n < 2:
#         return 0.0
#     stanrdDeviation = np.sqrt(M2 / (n - 1))
#     stanrdDeviationNormal = float(np.log1p(stanrdDeviation))
#     return stanrdDeviationNormal

# ?Can also use this method 
def windowDeviationPacketLength(window):
    if len(window) == 0:
        return 0
    lengths = [float(packet["Length"]) for packet in window]
    return float(np.std(lengths))

