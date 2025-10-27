
import json
import socket
import pandas as pd
from scapy.layers.inet import *
from scapy.all import *
from scapy.contrib.gtp import GTP_U_Header
import warnings
import pickle

# Suppress Scapy's verbose warnings
warnings.filterwarnings("ignore", category=UserWarning)

# --- CONFIGURATION ---
XAPP_HOST = '192.168.70.1'    # IP of the machine running the RIC/xApp (likely the AMF's IP in this setup)
XAPP_PORT = 8080              # Arbitrary port for communication with the xApp
CAPTURE_INTERFACE = "eth0"    # Interface inside the UPF container that sees the de-tunneled user traffic
WINDOW_SIZE = 10              # Number of packets to analyze per user before sending a report

# --- FEATURE EXTRACTION LOGIC ---
# Reverse mappings based on the traffic generator script
# This translates network data back into the categorical features the model was trained on.
PORT_TO_SERVICE = {
    80: 'http', 443: 'https', 21: 'ftp', 20: 'ftp_data', 25: 'smtp', 110: 'pop_3',
    23: 'telnet', 143: 'imap4', 22: 'ssh', 53: 'domain', 7: 'echo', 9: 'discard',
}

flow_data = {
    'protocol_type': 'other',
    'service': 'other',
    'src_bytes': 0,
    'dst_bytes': 0
}
packet_count = 0


def extract_features(packet):
    if not packet.haslayer(IP):
        return None

    if packet.haslayer(TCP):
        flow_data['protocol_type'] = 'tcp'
        proto_layer = packet[TCP]
    elif packet.haslayer(UDP):
        flow_data['protocol_type'] = 'udp'
        proto_layer = packet[UDP]
    elif packet.haslayer(ICMP):
        flow_data['protocol_type'] = 'icmp'
        proto_layer = packet[ICMP]
    else:
        return None # We only care about TCP, UDP, ICMP for this model

    # 2. Get Service (from destination port)
    if hasattr(proto_layer, 'dport'):
        flow_data['service'] = PORT_TO_SERVICE.get(proto_layer.dport, 'other')

    # 4 & 5. Get Bytes (payload size)
    # Traffic from UE (e.g. 12.2.1.2 -> 12.2.1.1) is 'src_bytes'
    if packet[IP].src == "12.2.1.2":
        if packet.haslayer(Raw):
            flow_data['src_bytes'] += len(packet[Raw].load)
    # Traffic to UE is 'dst_bytes'
    else:
        if packet.haslayer(Raw):
            flow_data['dst_bytes'] += len(packet[Raw].load)

def packet_handler(packet):
    # We expect GTP-U encapsulated traffic. The inner packet has the UE's IP.
    if not packet.haslayer(GTP_U_Header) or not packet[GTP_U_Header].haslayer(IP):
        return

    extract_features(packet)

    global packet_count

    packet_count = packet_count + 1

    # If window is full, process and report
    if packet_count >= WINDOW_SIZE:
        print(f"Window full, reporting traffic...")

        report_to_xapp()
        
        packet_count = 0

# --- COMMUNICATION WITH XAPP ---
def report_to_xapp():
    sst = 1
    sd = 1
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((XAPP_HOST, XAPP_PORT))

            report_data = {
                "sst": sst,
                "sd": sd,
                "protocol_type": flow_data['protocol_type'],
                "service": flow_data['service'],
                "src_bytes": flow_data['src_bytes'],
                "dst_bytes": flow_data['dst_bytes']
            }
            message = json.dumps(report_data)
            s.sendall(f"{message}\n".encode())
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

    # The store=0 argument prevents Scapy from keeping all packets in memory.
    try:
        sniff(iface=CAPTURE_INTERFACE, prn=packet_handler, store=0)
    except Exception as e:
        print(f"An error occurred during packet sniffing: {e}")
        print("Please ensure this script is run with root privileges and the correct interface is specified.")
