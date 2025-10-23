# AI-Driven Anomaly Detection Server (ADS) for O-RAN 5G Slicing
#
# Author: Based on the research by Tsourdinis et al.
# Paper: "AI-Driven Network Intrusion Detection and Resource Allocation in Real-World O-RAN 5G Networks"
#
# This script is designed to run within the custom UPF Docker container.
# Its purpose is to:
# 1. Capture de-encapsulated user traffic in real-time.
# 2. Extract specific features from each packet.
# 2.1 Encrypt
# 2,2 Send to rApp
# 3. Use Random Forest model to classify traffic.
# 3.1 Send result back to "upf"
# 3.2 UPF Decrypts and sends result to rapp
# 5. Report the anomaly percentage for each user to the control xApp over a TCP socket.

import socket
import pandas as pd
from scapy.layers.inet import *
from scapy.all import *
from scapy.contrib.gtp import GTP_U_Header
import numpy as np
import warnings

# Suppress Scapy's verbose warnings
warnings.filterwarnings("ignore", category=UserWarning)

# --- CONFIGURATION ---
XAPP_HOST = '192.168.70.1'  # IP of the machine running the RIC/xApp (likely the AMF's IP in this setup)
XAPP_PORT = 8080              # Arbitrary port for communication with the xApp
CAPTURE_INTERFACE = "eth0"    # Interface inside the UPF container that sees the de-tunneled user traffic
WINDOW_SIZE = 30              # Number of packets to analyze per user before sending a report
PREPROCESSOR_PATH = ''

# --- DATA STRUCTURES ---
# This dictionary will hold the packet feature data for each UE's sliding window.
# Key: UE's inner IP address (e.g., '12.2.1.2')
# Value: A list of feature dictionaries for the last N packets.
ue_traffic_window = {}

# --- LOAD PRE-TRAINED ML COMPONENTS ---
# These must be loaded once at the start for efficiency.
try:
    print("Loading preprocessors...")
    preprocessor = 
    print("preprocessors loaded successfully.")
except FileNotFoundError:
    print(f"ERROR: preprocessor files not found. Make sure '{PREPROCESSOR_PATH}' is in the same directory.")
    exit(1)

# --- FEATURE EXTRACTION LOGIC ---
# Reverse mappings based on the traffic generator script
# This translates network data back into the categorical features the model was trained on.
PORT_TO_SERVICE = {
    80: 'http', 443: 'https', 21: 'ftp', 20: 'ftp_data', 25: 'smtp', 110: 'pop_3',
    23: 'telnet', 143: 'imap4', 22: 'ssh', 53: 'domain', 7: 'echo', 9: 'discard',
}

FLAG_TO_DATASET = {
    'S': 'S0', 'R': 'RSTO', 'RA': 'RSTR', 'PA': 'SF', 'SA': 'S1' # Simplified mapping
}

def extract_features(packet):
    """
    Extracts the 5 key features from a Scapy packet as required by the ML model.
    This function assumes it's being passed the *inner* IP packet (after GTP de-tunneling).
    """
    if not packet.haslayer(IP):
        return None

    # Default values
    features = {
        'protocol_type': 'other',
        'service': 'other',
        'flag': 'OTH',
        'src_bytes': 0,
        'dst_bytes': 0
    }

    # 1. Get Protocol
    if packet.haslayer(TCP):
        features['protocol_type'] = 'tcp'
        proto_layer = packet[TCP]
        # 3. Get Flag (for TCP only)
        # Scapy flags are represented as a string like 'S' for SYN, 'A' for ACK, etc.
        features['flag'] = FLAG_TO_DATASET.get(str(proto_layer.flags), 'OTH')
    elif packet.haslayer(UDP):
        features['protocol_type'] = 'udp'
        proto_layer = packet[UDP]
    elif packet.haslayer(ICMP):
        features['protocol_type'] = 'icmp'
        proto_layer = packet[ICMP]
    else:
        return None # We only care about TCP, UDP, ICMP for this model

    # 2. Get Service (from destination port)
    if hasattr(proto_layer, 'dport'):
        features['service'] = PORT_TO_SERVICE.get(proto_layer.dport, 'other')

    # 4 & 5. Get Bytes (payload size)
    # The paper differentiates src and dst bytes, which implies analyzing a full connection.
    # Here, we approximate based on packet direction.
    # Traffic from UE (e.g. 12.2.1.2 -> 12.2.1.1) is 'src_bytes'
    if packet[IP].src.startswith("12."):
         if packet.haslayer(Raw):
             features['src_bytes'] = len(packet[Raw].load)
    # Traffic to UE is 'dst_bytes'
    else:
        if packet.haslayer(Raw):
            features['dst_bytes'] = len(packet[Raw].load)

    return features

# --- MAIN PACKET PROCESSING AND ML INFERENCE ---
def process_and_predict(ue_ip):
    """
    Takes a full window of traffic for a UE, preprocesses it,
    gets a prediction from the model, and returns the anomaly percentage.
    """
    window_data = ue_traffic_window[ue_ip]
    df = pd.DataFrame(window_data)

    # Separate categorical and numerical features for preprocessing
    categorical_features = ['protocol_type', 'service', 'flag']
    numerical_features = ['src_bytes', 'dst_bytes']

    # Apply One-Hot Encoding and Min-Max Scaling
    encoded_data = encoder.transform(df[categorical_features])
    scaled_data = scaler.transform(df[numerical_features])
    # Combine preprocessed features
    processed_df = np.hstack([encoded_data.toarray(), scaled_data])

    return processed_df

def packet_handler(packet):
    """
    This is the callback function called by Scapy's sniff() for each captured packet.
    It manages the sliding window and triggers the prediction and reporting.
    """
    # We expect GTP-U encapsulated traffic. The inner packet has the UE's IP.
    if not packet.haslayer(GTP_U_Header) or not packet[GTP_U_Header].haslayer(IP):
        return

    inner_ip_packet = packet[GTP_U_Header][IP]
    ue_ip = inner_ip_packet.src

    # Identify UE based on source IP prefix, as per traffic generator
    if not ue_ip.startswith("12."):
        return

    # Extract features from the inner packet
    features = extract_features(inner_ip_packet)
    if features is None:
        return

    # Initialize window for new UE
    if ue_ip not in ue_traffic_window:
        ue_traffic_window[ue_ip] = []

    # Add features to the UE's window
    ue_traffic_window[ue_ip].append(features)

    # If window is full, process and report
    if len(ue_traffic_window[ue_ip]) >= WINDOW_SIZE:
        print(f"Window full for UE {ue_ip}. Analyzing traffic...")
        
        # Get anomaly percentage from the ML model
        data = process_and_predict(ue_ip)
        
        print(f"Analysis complete for UE {ue_ip}: DATA = {data}")

        # Send the result to the xApp
        report_to_xapp(ue_ip, data)

        # Clear the window for the next batch of packets
        ue_traffic_window[ue_ip] = []

# --- COMMUNICATION WITH XAPP ---
def report_to_xapp(ue_ip, percentage):
    """
    Connects to the xApp and sends the anomaly report.
    Format: "UE_IP,ANOMALY_PERCENTAGE"
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((XAPP_HOST, XAPP_PORT))
            message = f"{ue_ip},{percentage}"
            s.sendall(message.encode('utf-8'))
            print(f"Report sent to xApp: {message}")
    except ConnectionRefusedError:
        print(f"ERROR: Connection to xApp at {XAPP_HOST}:{XAPP_PORT} refused. Is the xApp running?")
    except Exception as e:
        print(f"An error occurred while sending report to xApp: {e}")


# --- MAIN EXECUTION BLOCK ---
if __name__ == "__main__":
    print("--- Anomaly Detection Server for OAI 5G UPF ---")
    print(f"Starting packet capture on interface: {CAPTURE_INTERFACE}")
    print(f"Will report to xApp at: {XAPP_HOST}:{XAPP_PORT}")

    # Start sniffing packets. The packet_handler function will be called for each packet.
    # The store=0 argument prevents Scapy from keeping all packets in memory.
    try:
        sniff(iface=CAPTURE_INTERFACE, prn=packet_handler, store=0)
    except Exception as e:
        print(f"An error occurred during packet sniffing: {e}")
        print("Please ensure this script is run with root privileges and the correct interface is specified.")
