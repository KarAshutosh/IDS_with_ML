import numpy as np
from sklearn.ensemble import IsolationForest
from scapy.all import *
import warnings

warnings.filterwarnings("ignore")

# Function to extract features from network packets
def extract_features(packet):
    features = []

    # Basic packet features
    features.append(packet.time)
    features.append(len(packet))
    features.append(packet[TCP].flags)
    features.append(packet[IP].ttl)

    return features

# Function to preprocess packet data
def preprocess_data(packets):
    data = []
    for packet in packets:
        features = extract_features(packet)
        data.append(features)
    return np.array(data)

# Load the dataset (you need to provide your own pcap file)
packets = rdpcap("network_traffic.pcap")

# Preprocess the data
data = preprocess_data(packets)

# Train the Isolation Forest model
model = IsolationForest(contamination=0.01, random_state=42)
model.fit(data)

# Detect anomalies
predictions = model.predict(data)
anomalies = np.where(predictions == -1)[0]

print("Detected anomalies at indices:", anomalies)
