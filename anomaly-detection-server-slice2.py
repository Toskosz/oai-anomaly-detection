
import socket
import time
import pandas as pd
import joblib
from scapy.all import sniff, IP, TCP, UDP

# Load the trained model and preprocessor
model = joblib.load('notebooks/random_forest_model.pkl')
preprocessor = joblib.load('notebooks/preprocessor.pkl')

# -- Network configuration --
XAPP_IP = '192.168.70.1'
XAPP_PORT = 8080
INTERFACE = 'eth0'  # Interface to sniff on, change if needed

# -- Slice identification --
SST = 1
SD = 5

# -- Global variables --
normal_count = 0
anomaly_count = 0

def get_service(src_port, dst_port):
    # A simple service mapping based on port numbers
    if dst_port == 80 or src_port == 80:
        return 'http'
    elif dst_port == 443 or src_port == 443:
        return 'https'
    elif dst_port == 21 or src_port == 21:
        return 'ftp'
    elif dst_port == 22 or src_port == 22:
        return 'ssh'
    elif dst_port == 23 or src_port == 23:
        return 'telnet'
    elif dst_port == 25 or src_port == 25:
        return 'smtp'
    elif dst_port == 53 or src_port == 53:
        return 'domain_u'
    else:
        return 'other'

def packet_handler(packet):
    global normal_count, anomaly_count

    if IP in packet:
        # -- Feature extraction --
        duration = 0  # Placeholder
        protocol_type = ''
        if TCP in packet:
            protocol_type = 'tcp'
        elif UDP in packet:
            protocol_type = 'udp'
        else:
            protocol_type = 'icmp'

        service = get_service(packet.sport, packet.dport) if packet.haslayer(TCP) or packet.haslayer(UDP) else 'other'
        flag = packet[TCP].flags if TCP in packet else 'OTH'
        src_bytes = len(packet[IP].payload)
        dst_bytes = 0  # Placeholder
        land = 1 if packet[IP].src == packet[IP].dst else 0
        wrong_fragment = 0  # Placeholder
        urgent = 0  # Placeholder
        hot = 0  # Placeholder
        num_failed_logins = 0  # Placeholder
        logged_in = 0  # Placeholder
        num_compromised = 0  # Placeholder
        root_shell = 0  # Placeholder
        su_attempted = 0  # Placeholder
        num_root = 0  # Placeholder
        num_file_creations = 0  # Placeholder
        num_shells = 0  # Placeholder
        num_access_files = 0  # Placeholder
        num_outbound_cmds = 0  # Placeholder
        is_host_login = 0  # Placeholder
        is_guest_login = 0  # Placeholder
        count = 0  # Placeholder
        srv_count = 0  # Placeholder
        serror_rate = 0.0  # Placeholder
        srv_serror_rate = 0.0  # Placeholder
        rerror_rate = 0.0  # Placeholder
        srv_rerror_rate = 0.0  # Placeholder
        same_srv_rate = 0.0  # Placeholder
        diff_srv_rate = 0.0  # Placeholder
        srv_diff_host_rate = 0.0  # Placeholder
        dst_host_count = 0  # Placeholder
        dst_host_srv_count = 0  # Placeholder
        dst_host_same_srv_rate = 0.0  # Placeholder
        dst_host_diff_srv_rate = 0.0  # Placeholder
        dst_host_same_src_port_rate = 0.0  # Placeholder
        dst_host_srv_diff_host_rate = 0.0  # Placeholder
        dst_host_serror_rate = 0.0  # Placeholder
        dst_host_srv_serror_rate = 0.0  # Placeholder
        dst_host_rerror_rate = 0.0  # Placeholder
        dst_host_srv_rerror_rate = 0.0  # Placeholder

        # Create a DataFrame for the single packet
        packet_data = {
            'duration': [duration], 'protocol_type': [protocol_type], 'service': [service], 'flag': [flag],
            'src_bytes': [src_bytes], 'dst_bytes': [dst_bytes], 'land': [land], 'wrong_fragment': [wrong_fragment],
            'urgent': [urgent], 'hot': [hot], 'num_failed_logins': [num_failed_logins], 'logged_in': [logged_in],
            'num_compromised': [num_compromised], 'root_shell': [root_shell], 'su_attempted': [su_attempted],
            'num_root': [num_root], 'num_file_creations': [num_file_creations], 'num_shells': [num_shells],
            'num_access_files': [num_access_files], 'num_outbound_cmds': [num_outbound_cmds],
            'is_host_login': [is_host_login], 'is_guest_login': [is_guest_login], 'count': [count],
            'srv_count': [srv_count], 'serror_rate': [serror_rate], 'srv_serror_rate': [srv_serror_rate],
            'rerror_rate': [rerror_rate], 'srv_rerror_rate': [srv_rerror_rate], 'same_srv_rate': [same_srv_rate],
            'diff_srv_rate': [diff_srv_rate], 'srv_diff_host_rate': [srv_diff_host_rate],
            'dst_host_count': [dst_host_count], 'dst_host_srv_count': [dst_host_srv_count],
            'dst_host_same_srv_rate': [dst_host_same_srv_rate], 'dst_host_diff_srv_rate': [dst_host_diff_srv_rate],
            'dst_host_same_src_port_rate': [dst_host_same_src_port_rate],
            'dst_host_srv_diff_host_rate': [dst_host_srv_diff_host_rate],
            'dst_host_serror_rate': [dst_host_serror_rate], 'dst_host_srv_serror_rate': [dst_host_srv_serror_rate],
            'dst_host_rerror_rate': [dst_host_rerror_rate], 'dst_host_srv_rerror_rate': [dst_host_srv_rerror_rate]
        }
        df = pd.DataFrame(packet_data)

        # Preprocess and predict
        processed_df = preprocessor.transform(df)
        prediction = model.predict(processed_df)

        if prediction[0] == 'normal':
            normal_count += 1
        else:
            anomaly_count += 1

def send_stats(sock):
    global normal_count, anomaly_count
    message = f"sst:{SST},sd:{SD},normal:{normal_count},anomaly:{anomaly_count}"
    try:
        sock.sendall(message.encode('utf-8'))
        print(f"Sent: {message}")
    except socket.error as e:
        print(f"Error sending data: {e}")
        return False
    return True

def main():
    # -- Connect to xApp --
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((XAPP_IP, XAPP_PORT))
            print(f"Connected to xApp at {XAPP_IP}:{XAPP_PORT}")
            break
        except socket.error as e:
            print(f"Failed to connect to xApp: {e}. Retrying in 5 seconds...")
            time.sleep(5)

    # -- Start sniffing and sending stats --
    def periodic_send():
        while True:
            time.sleep(1)
            if not send_stats(sock):
                break
    
    import threading
    sender_thread = threading.Thread(target=periodic_send)
    sender_thread.daemon = True
    sender_thread.start()

    print(f"Starting to sniff on interface {INTERFACE}")
    sniff(iface=INTERFACE, prn=packet_handler, store=0)

    sock.close()

if __name__ == "__main__":
    main()
