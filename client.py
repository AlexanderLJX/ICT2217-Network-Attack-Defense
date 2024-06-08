import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import time

# Fetch the public key from the server
response = requests.get('https://127.0.0.1/public_key', verify=False)
pem_public_key = response.content

# Load the public key
public_key = serialization.load_pem_public_key(pem_public_key)

# Encrypt the password
password = "password123"
encrypted_password = public_key.encrypt(
    password.encode('utf-8'),
    padding.PKCS1v15()
)

# Send the encrypted password to the login endpoint
login_data = {
    'username': 'admin',
    'password': encrypted_password.decode('latin1')
}

# Measure response time
start_time = time.time()
response = requests.post('https://127.0.0.1/login', data=login_data, verify=False)
end_time = time.time()

response_time = end_time - start_time
print(f"Response time: {response_time} seconds")
print(response.text)
