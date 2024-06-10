import random
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Util.Padding import unpad

# Generate RSA keys
key = RSA.generate(2048)
public_key = key.publickey()
cipher = PKCS1_v1_5.new(public_key)

# Encrypt a message
message = b'Attack at dawn'
ciphertext = cipher.encrypt(message)

# Padding oracle that simulates timing differences
def padding_oracle(ciphertext):
    try:
        sentinel = b""
        cipher = PKCS1_v1_5.new(key)
        decrypted_message = cipher.decrypt(ciphertext, sentinel)
        unpad(decrypted_message, 128)  # Assume block size is 128 bytes
        return True  # Valid padding
    except (ValueError, TypeError):
        return False  # Invalid padding

# Simulate the timing difference for valid/invalid padding
def timing_oracle(ciphertext):
    start_time = time.time()
    valid_padding = padding_oracle(ciphertext)
    end_time = time.time()
    time.sleep(random.uniform(0, 0.05))  # Add random delay for more realism
    return valid_padding, end_time - start_time

# Attack function
def rsa_padding_timing_attack(ciphertext, public_key):
    # Implementation of the attack (simplified and illustrative)
    # Normally, this would involve a complex mathematical attack
    # Here we are demonstrating the concept
    decrypted = bytearray(len(ciphertext))
    print(len(ciphertext))
    for i in range(len(ciphertext)):
        print(i)
        for byte in range(256):
            guess = ciphertext[:i] + bytes([byte]) + ciphertext[i+1:]
            valid, timing = timing_oracle(guess)
            if valid:
                decrypted[i] = byte
                break
    return decrypted

# Perform the attack
decrypted_message = rsa_padding_timing_attack(ciphertext, public_key)
print("Decrypted message:", decrypted_message)
