import socket
import json
import time
import random

# This mock client will pretend to be the UPF, sending flow data.

ORK_IP = "127.0.0.1"
ORK_PORT = 8585

def main():

    src_bytes_max = 62825648
    dst_bytes_max = 62825648
    protocol_type = ['tcp', 'icmp', 'udp']
    service = ['private', 'ftp_data', 'eco_i', 'telnet', 'http', 'smtp', 'ftp', 'ldap', 'pop_3',
            'courier', 'discard', 'ecr_i', 'imap4', 'domain_u', 'mtp', 'systat', 'iso_tsap',
            'other', 'csnet_ns', 'finger', 'uucp', 'whois', 'netbios_ns', 'link', 'Z39_50',
            'sunrpc', 'auth', 'netbios_dgm', 'uucp_path', 'vmnet', 'domain', 'name', 'pop_2',
            'http_443', 'urp_i', 'login', 'gopher', 'exec', 'time', 'remote_job', 'ssh',
            'kshell', 'sql_net', 'shell', 'hostnames', 'echo', 'daytime', 'pm_dump', 'IRC',
            'netstat', 'ctf', 'nntp', 'netbios_ssn', 'tim_i', 'supdup', 'bgp', 'nnsp', 'rje',
            'printer', 'efs', 'X11', 'ntp_u', 'klogin', 'tftp_u']

    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                print(f"[INFO] Mock UPF trying to connect to Orchestrator at {ORK_IP}:{ORK_PORT}...")
                s.connect((ORK_IP, ORK_PORT))
                print("[INFO] Connected to Orchestrator.")

                for _ in range(10):
                    flow_data = {
                        "protocol_type": random.choice(protocol_type),
                        "service": random.choice(service),
                        "src_bytes": random.randint(0, src_bytes_max),
                        "dst_bytes": random.randint(0, dst_bytes_max)
                    }
                    message = json.dumps(flow_data)
                    print(f"[INFO] Sending to orchestrator: {message}")
                    s.sendall(f"{message}\n".encode())
                    time.sleep(0.8)

                print("[INFO] Finished sending data. Closing connection.")
            break # Exit after successful run

        except ConnectionRefusedError:
            print("[ERROR] Connection refused. Is the orchestrator running? Retrying in 5 seconds...")
            time.sleep(5)

if __name__ == "__main__":
    main()
