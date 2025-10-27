
import json
import socket
from scapy.layers.inet import *
from scapy.all import *
from scapy.contrib.gtp import GTP_U_Header
import warnings

# Suppress Scapy's verbose warnings
warnings.filterwarnings("ignore", category=UserWarning)

# --- CONFIGURATION ---
XAPP_HOST = '192.168.70.1'    # IP of the machine running the RIC/xApp (likely the AMF's IP in this setup)
XAPP_PORT = 8080              # Arbitrary port for communication with the xApp
CAPTURE_INTERFACE = "tun0"    # Interface inside the UPF container that sees the de-tunneled user traffic
WINDOW_SIZE = 10              # Number of packets to analyze per user before sending a report

# --- FEATURE EXTRACTION LOGIC ---
# Reverse mappings based on the traffic generator script
# This translates network data back into the categorical features the model was trained on.
PORT_TO_SERVICE = {
    80: 'http', 443: 'https', 21: 'ftp', 20: 'ftp_data', 25: 'smtp', 110: 'pop_3',
    23: 'telnet', 143: 'imap4', 22: 'ssh', 53: 'domain', 7: 'echo', 9: 'discard',
}

sock = None

flow_data = {
    'protocol_type': 'other',
    'service': 'other',
    'src_bytes': 0,
    'dst_bytes': 0
}
packet_count = 0

def connect_to_xapp():
    global sock
    # Close any existing broken socket
    if sock:
        try:
            sock.close()
        except Exception:
            pass # Ignore errors on closing a broken socket

    while True:
        try:
            print(f"Attempting to connect to xApp at {XAPP_HOST}:{XAPP_PORT}...")
            # Create a new socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Set a timeout for the connection attempt
            sock.settimeout(5.0) 
            sock.connect((XAPP_HOST, XAPP_PORT))
            # Set timeout to None (blocking) for normal operation
            sock.settimeout(None) 
            
            print("Successfully connected to xApp.")
            break # Exit the loop on success
        except (ConnectionRefusedError, socket.timeout):
            print("Connection failed. Retrying in 5 seconds...")
            time.sleep(5)
        except Exception as e:
            print(f"An unexpected error occurred during connection: {e}. Retrying in 5s...")
            time.sleep(5)

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
    sd = 5

    report_data = {
        "sst": sst,
        "sd": sd,
        "protocol_type": flow_data['protocol_type'],
        "service": flow_data['service'],
        "src_bytes": flow_data['src_bytes'],
        "dst_bytes": flow_data['dst_bytes']
    }
    message = json.dumps(report_data)

    global sock
    try:
        sock.sendall(f"{message}\n".encode())
        print(f"Report sent to xApp: {message}")
    except (BrokenPipeError, ConnectionResetError, AttributeError, OSError) as e:
        print(f"Connection lost: {e}. Reconnecting and retrying...")
        connect_to_xapp() # Re-establish connection
        try:
            sock.sendall(f"{message}\n".encode()) # Retry sending
            print("Report sent successfully after reconnecting.")
        except Exception as e2:
            print(f"Failed to send even after reconnecting: {e2}")

# --- MAIN EXECUTION BLOCK ---
if __name__ == "__main__":
    print("--- Anomaly Detection Server for OAI 5G UPF ---")
    print(f"Starting packet capture on interface: {CAPTURE_INTERFACE}")
    print(f"Will report to xApp at: {XAPP_HOST}:{XAPP_PORT}")

    connect_to_xapp()

    # The store=0 argument prevents Scapy from keeping all packets in memory.
    try:
        subnet_filter = "net 12.1.1.0/24"
        sniff(iface=CAPTURE_INTERFACE, filter=subnet_filter, prn=packet_handler, store=False)
    except Exception as e:
        print(f"An error occurred during packet sniffing: {e}")
        print("Please ensure this script is run with root privileges and the correct interface is specified.")
