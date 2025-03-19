import numpy as np 
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import shap
import pickle
import os

# Feature names list for SHAP explanation
features = [
    # General stats
    "averagepacketlength",
    "deviationOfPacketLength",
    "minPacketLength",
    "MaxPacketLength",
    "outOfOrderPacketRatio",
    "packetRate",
    "windowTimeLength",
    "meanTimeBetweenPakets",
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
    "ModbusAvgResponseTime",
    "ModbusMaxResponseTime",
    "ModbusMinResponseTime",
    "ModbusDeviationResponseTime"
]

# Helper function to combine multiple window data points into a single list
def combineData(windows):
    """
    Flattens the nested structure of window data into a list of feature vectors
    """
    combined_list = []
    for window in windows:
        window_features = []
        for protocol in window:
            # Check if the protocol data is iterable (should be)
            if hasattr(protocol, '__iter__'):
                for value in protocol:
                    window_features.append(value)
            else:
                # Fallback in case of scalar values
                window_features.append(protocol)
        combined_list.append(window_features)
    return combined_list

def train_isolation_forest(clean_data, model_path="model/isolation_forest.pkl", scaler_path="model/scaler.pkl"):
    """
    Train an Isolation Forest model on clean baseline data and save the model
    
    Args:
        clean_data: List of clean network traffic windows
        model_path: Path to save the trained model
        scaler_path: Path to save the feature scaler
        
    Returns:
        Trained model and scaler
    """
    # Ensure the model directory exists
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    
    # Prepare the clean data
    clean_formatted = combineData(clean_data)
    clean_array = np.array(clean_formatted)
    
    # Create and fit the scaler
    scaler = StandardScaler()
    train_clean_scaled = scaler.fit_transform(clean_array)
    
    print(f"Training Isolation Forest on {len(clean_data)} clean windows...")
    
    # Create and train the Isolation Forest model
    # Using a lower contamination value since we're training on clean data
    iso_forest = IsolationForest(
        n_estimators=500,  # More trees for better stability
        contamination=0.01,  # Expecting very few anomalies in clean data
        max_samples="auto",
        random_state=42  # For reproducibility
    )
    
    iso_forest.fit(train_clean_scaled)
    
    # Save the model and scaler
    with open(model_path, 'wb') as f:
        pickle.dump(iso_forest, f)
    
    with open(scaler_path, 'wb') as f:
        pickle.dump(scaler, f)
        
    print(f"Model and scaler saved to {os.path.dirname(model_path)}")
    
    return iso_forest, scaler

def load_model(model_path="model/isolation_forest.pkl", scaler_path="model/scaler.pkl"):
    """
    Load a previously trained Isolation Forest model and scaler
    
    Returns:
        Tuple of (model, scaler)
    """
    try:
        with open(model_path, 'rb') as f:
            iso_forest = pickle.load(f)
            
        with open(scaler_path, 'rb') as f:
            scaler = pickle.load(f)
            
        return iso_forest, scaler
    except FileNotFoundError:
        print(f"Model files not found at {model_path}. Please train the model first.")
        return None, None

def evaluate_window(window, iso_forest=None, scaler=None, threshold=-0.2, explain=True):
    """
    Evaluate a single window against the trained Isolation Forest model
    
    Args:
        window: A single window of network traffic data
        iso_forest: Trained Isolation Forest model (will load from file if None)
        scaler: Fitted StandardScaler (will load from file if None)
        threshold: Custom decision threshold (lower = more sensitive)
        explain: Whether to generate SHAP explanations for anomalies
        
    Returns:
        Dictionary with anomaly results
    """
    # Load model if not provided
    if iso_forest is None or scaler is None:
        iso_forest, scaler = load_model()
        if iso_forest is None:
            return {"error": "Model not loaded. Please train model first."}
    
    # Format the window data
    window_formatted = combineData([window])  # Need to wrap in list since combineData expects multiple windows
    window_array = np.array(window_formatted)
    
    # Scale the data
    window_scaled = scaler.transform(window_array)
    
    # Get anomaly score
    anomaly_score = iso_forest.decision_function(window_scaled)[0]
    
    # Determine if anomaly based on threshold
    is_anomaly = anomaly_score < threshold
    
    result = {
        "is_anomaly": is_anomaly,
        "anomaly_score": anomaly_score,
        "classification": "Anomaly" if is_anomaly else "Normal"
    }
    
    # Generate SHAP explanation if it's an anomaly and explanation is requested
    if is_anomaly and explain:
        try:
            explainer = shap.Explainer(iso_forest, pd.DataFrame(window_scaled, columns=features))
            shap_values = explainer(window_scaled)
            
            # Get top features contributing to anomaly decision
            feature_importances = []
            for idx, val in enumerate(shap_values.values[0]):
                if val < 0:  # Negative SHAP values contribute to anomaly classification
                    feature_importances.append({
                        "feature_name": features[idx] if idx < len(features) else f"Feature_{idx}",
                        "feature_value": window_array[0][idx],
                        "shap_value": val,
                        "contribution": abs(val)
                    })
            
            # Sort by contribution magnitude
            feature_importances.sort(key=lambda x: x["contribution"], reverse=True)
            
            # Add top contributing features to result
            result["explanation"] = {
                "top_features": feature_importances[:5],  # Top 5 contributing features
                "base_value": float(shap_values.base_values[0])
            }
        except Exception as e:
            result["explanation_error"] = str(e)
    
    return result

def monitor_traffic(new_windows, iso_forest=None, scaler=None, threshold=-0.2):
    """
    Monitor a stream of traffic windows for anomalies
    
    Args:
        new_windows: List of new windows to evaluate
        iso_forest: Trained Isolation Forest model (will load from file if None)
        scaler: Fitted StandardScaler (will load from file if None)
        threshold: Custom decision threshold (lower = more sensitive)
        
    Returns:
        List of evaluation results for each window
    """
    # Load model if not provided
    if iso_forest is None or scaler is None:
        iso_forest, scaler = load_model()
        if iso_forest is None:
            return [{"error": "Model not loaded. Please train model first."}]
    
    results = []
    anomaly_count = 0
    
    for i, window in enumerate(new_windows):
        result = evaluate_window(window, iso_forest, scaler, threshold)
        result["window_id"] = i
        results.append(result)
        
        if result["is_anomaly"]:
            anomaly_count += 1
            print(f"Window {i}: ANOMALY DETECTED! Score: {result['anomaly_score']:.4f}")
            if "explanation" in result:
                print("  Top contributing factors:")
                for feature in result["explanation"]["top_features"]:
                    print(f"  - {feature['feature_name']}: {feature['feature_value']:.4f} (impact: {feature['shap_value']:.4f})")
        else:
            print(f"Window {i}: Normal (Score: {result['anomaly_score']:.4f})")
    
    print(f"\nAnalysis complete: {anomaly_count} anomalies detected in {len(new_windows)} windows")
    return results

# Original function for backwards compatibility, now calls the new functions
def isoFor(clean, dirty=None):
    """
    Train on clean data and optionally test on dirty data
    """
    # Train and save model on clean data
    iso_forest, scaler = train_isolation_forest(clean)
    
    # If dirty data is provided, evaluate it
    if dirty is not None:
        print("\nEvaluating potentially dirty windows:")
        results = monitor_traffic(dirty, iso_forest, scaler)
        
        # Count anomalies
        anomaly_count = sum(1 for r in results if r["is_anomaly"])
        print(f"\nSummary: {anomaly_count} anomalies detected out of {len(dirty)} windows")
    
    return iso_forest, scaler