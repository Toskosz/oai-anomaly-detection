import pandas as pd
from scapy.layers.inet import *
from scapy.all import *
import time
import random
from scapy.contrib.gtp import GTP_U_Header


# Load data with the same column names as before
column_names = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty_level"]
test_df = pd.read_csv('Test.txt', header=None, names=column_names)

def generate_packet(row, orientation, size):

    service_ports = {
        'http': 80, 'https': 443, 'ftp': 21, 'ftp_data': 20, 'smtp': 25, 'pop_3': 110,
        'telnet': 23, 'imap4': 143, 'ssh': 22, 'domain': 53, 'gopher': 70,
        'systat': 11, 'daytime': 13, 'netstat': 15, 'echo': 7, 'discard': 9,
        'X11': 6000, 'urp_i': 5001, 'auth': 113, 'uucp_path': 117,
        'login': 513, 'shell': 514, 'printer': 515, 'efs': 520, 'temp': 525,
        'courier': 530, 'conference': 531, 'netnews': 532, 'netbios_ns': 137,
        'netbios_dgm': 138, 'netbios_ssn': 139, 'klogin': 543, 'kshell': 544,
        'ldap': 389, 'exec': 512, 'biff': 512, 'whois': 43, 'sql_net': 150,
        'ntp_u': 123, 'tftp_u': 69, 'IRC': 194, 'z39.50': 210,
        'pop_2': 109, 'sunrpc': 111, 'vmnet': 175, 'nntp': 119, 'private': 333, 'domain_u': 332,
        'uucp': 334, 'supdup': 335, 'pm_dump':336, 'mtp':337,  'other': 0  # Reserved for any non-specific services
    }
    
    flag_mapping = {
        'REJ': 'R',       # Rejected (usually not directly map to a TCP flag but can simulate with RST)
        'SF': 'PA',       # Standard data transmission (PSH, ACK)
        'RSTO': 'R',      # Connection reset with no payload
        'S0': 'S',        # Initial connection request (SYN)
        'RSTR': 'RA',     # Reset with acknowledgment
        'SH': 'S',        # SYN High - typically not a standard flag, assuming SYN for simulation
        'S3': 'SA',       # SYN, ACK - Part of a three-way handshake
        'S2': 'SA',       # Same as S3, for simplification
        'S1': 'SA',       # Same as S2, further simplification
        'RSTOS0': 'RS',   # Reset during SYN
        'OTH': ''         # No flags set
    }

    protocol = row['protocol_type'].lower()
    service = row['service']
    flag = flag_mapping.get(row['flag'], '')
    
    port = service_ports.get(service, 0)
    payload = 'X' * size

    src_ip = "12.1.1.130"
    dst_ip = "192.168.70.145"

    if orientation == 1:
        src_ip = "12.1.1.130"
        dst_ip = "192.168.70.145"

    if protocol == 'tcp':
        inner_packet = IP(src=src_ip, dst=dst_ip)/TCP(dport=port, flags=flag)/Raw(load=payload)
    elif protocol == 'udp':
        inner_packet = IP(src=src_ip, dst=dst_ip)/UDP(dport=port)/Raw(load=payload)
    else:
        inner_packet = IP(src=src_ip, dst=dst_ip)/ICMP()  # Default for other protocols

    # Encapsulate in GTP-U packet
    # gtp_packet = IP(src=src_ip, dst=dst_ip)/UDP(sport=2152, dport=2152)/GTP_U_Header(teid=1)/inner_packet

    return inner_packet

def simulate_traffic(flow):
    remaining_src_bytes = flow["src_bytes"] - 300
    remaining_dst_bytes = flow["dst_bytes"]

    # first packet is always from UE
    first_packet = generate_packet(flow, 0, 300)
    send(first_packet, iface="oaitun_ue1")
    
    while remaining_dst_bytes != 0 or remaining_src_bytes != 0:
        # 0 = src -> dst
        # 1 = response (dst -> src)
        packet_orientation = random.randint(0, 1)
        packet_size = 0

        while True:
            packet_size = random.randint(200, 1400)
            if packet_orientation == 0:
                if packet_size <= remaining_src_bytes:
                    remaining_src_bytes -= packet_size
                    break
                if remaining_src_bytes < 200:
                    packet_size = remaining_src_bytes 
                    remaining_src_bytes = 0
                    break
            else:
                if packet_size <= remaining_dst_bytes:
                    remaining_dst_bytes -= packet_size
                    break
                if remaining_dst_bytes < 200:
                    packet_size = remaining_dst_bytes 
                    remaining_dst_bytes = 0
                    break

        packet = generate_packet(flow, packet_orientation, packet_size)
        print(f"Sending GTP encapsulated packet with size: {len(bytes(packet_size))}")
        send(packet, iface="oaitun_ue1")  # Sending the main packet on the correct interface

random_row = test_df.sample(1).iloc[0]

simulate_traffic(random_row)
