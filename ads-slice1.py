import logging
from scapy.all import *
from scapy.layers.inet import *
from scapy.contrib.gtp import GTP_U_Header
import time

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

# Define the slice configuration
sst = 1
sd = 1

def connect_to_server():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while True:
        try:
            client_socket.connect(('192.168.70.1', 8080))
            logging.info("Connected to server.")
            break
        except ConnectionRefusedError:
            logging.info("Server not up yet. Retrying in 5 seconds...")
            time.sleep(5)
    return client_socket

# Mapping of ports to services
service_ports = {
    80: 'http', 443: 'https', 21: 'ftp', 20: 'ftp_data', 25: 'smtp', 110: 'pop_3',
    23: 'telnet', 143: 'imap4', 22: 'ssh', 53: 'domain', 70: 'gopher',
    11: 'systat', 13: 'daytime', 15: 'netstat', 7: 'echo', 9: 'discard',
    6000: 'X11', 5001: 'urp_i', 113: 'auth', 117: 'uucp_path',
    513: 'login', 514: 'shell', 515: 'printer', 520: 'efs', 525: 'temp',
    530: 'courier', 531: 'conference', 532: 'netnews', 137: 'netbios_ns',
    138: 'netbios_dgm', 139: 'netbios_ssn', 543: 'klogin', 544: 'kshell',
    389: 'ldap', 512: 'exec', 43: 'whois', 150: 'sql_net',
    123: 'ntp_u', 69: 'tftp_u', 194: 'IRC', 210: 'z39.50', 109: 'pop_2',
    111: 'sunrpc', 175: 'vmnet', 119: 'nntp', 332: 'domain_u', 333: 'private', 334: 'uucp', 335: 'supdup', 336: 'pm_dump', 337: 'mtp', 0: 'other'
}

def interpret_flags(flags):
    # Convert flag object to a string
    flag_str = ''
    if flags & 0x01: flag_str += 'F'  # FIN
    if flags & 0x02: flag_str += 'S'  # SYN
    if flags & 0x04: flag_str += 'R'  # RST
    if flags & 0x08: flag_str += 'P'  # PSH
    if flags & 0x10: flag_str += 'A'  # ACK
    if flags & 0x20: flag_str += 'U'  # URG
    if flags & 0x40: flag_str += 'E'  # ECE
    if flags & 0x80: flag_str += 'C'  # CWR
    return flag_str

def decapsulate_gtp(packet):
    if GTP_U_Header in packet:
        gtp_payload = packet[GTP_U_Header].payload
        if IP in gtp_payload:
            return gtp_payload[IP]
    return None

def report_to_xapp(data):
    message = json.dumps(data)

    global sock
    try:
        sock.sendall(f"{message}\n".encode())
        print(f"Report sent to xApp: {message}")
    except (BrokenPipeError, ConnectionResetError, AttributeError, OSError) as e:
        print(f"Connection lost: {e}.")

def process_packet(packet):
    # Decapsulate GTP-U packet if present
    # ip_packet = decapsulate_gtp(packet)
    # if not ip_packet:
    #     # If not a GTP-U packet, check if it's a regular IP packet
    #     if IP in packet:
    ip_packet = packet[IP]

    if ip_packet:
        protocol_type = 'unknown'
        service = 'other'
        src_bytes = 0
        dst_bytes = 0

        src_ip = ip_packet.src
        dst_ip = ip_packet.dst
        logging.info(f"Source IP: {src_ip}, Destination IP: {dst_ip}")

        if TCP in ip_packet:
            protocol_type = 'tcp'
            dst_port = ip_packet[TCP].dport
            service = service_ports.get(dst_port, 'other')
            src_bytes = len(ip_packet[TCP].payload)
            dst_bytes = src_bytes
        elif UDP in ip_packet:
            protocol_type = 'udp'
            dst_port = ip_packet[UDP].dport
            service = service_ports.get(dst_port, 'other')
            src_bytes = len(ip_packet[UDP].payload)
            dst_bytes = src_bytes
        elif ICMP in ip_packet:
            protocol_type = 'icmp'
            src_bytes = len(ip_packet[ICMP].payload)
            dst_bytes = src_bytes

        packet_features = {
            'sst': sst,
            'sd': sd,
            'protocol_type': protocol_type,
            'service': service,
            'src_bytes': src_bytes,
            'dst_bytes': dst_bytes
        }

        logging.info(f"Packet features: {packet_features}")

        report_to_xapp(packet_features)

def capture_traffic():
    subnet_filter = "net 12.1.1.0/24"
    while True:
        try:
            # Continuously sniff packets only from the specified subnet
            sniff(iface='tun0', filter=subnet_filter, prn=process_packet, store=False)
        except KeyboardInterrupt:
            logging.info("Packet capture stopped by user.")
            break
        except Exception as e:
            logging.error(f"Error during packet capture: {e}")
            time.sleep(10)  # Sleep for a bit before trying to capture packets again

def main():
    global sock
    while True:
        try:
            sock = socket.create_connection(("192.168.70.1", 8080))
            logging.info("Connected to the server")
            break
        except ConnectionRefusedError:
            logging.error("Server is not up yet. Retrying in 5 seconds...")
            time.sleep(5)
    capture_traffic()

if __name__ == "__main__":
    main()
