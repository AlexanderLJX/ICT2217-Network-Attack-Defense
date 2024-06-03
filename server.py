import socket
import threading
import ssl
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from hashlib import sha256
from OpenSSL import SSL, crypto

# Define the listening port
port = 443

# Define the secret key
secret_key = b"ThisIsASecretKey"

# Define the username and password
username = "admin"
password = "password"

# Vulnerable RSA decryption functions
def decrypt_premaster_secret_openssl(encrypted_premaster_secret):
    # Load the RSA private key
    key = RSA.import_key(open("private_key.pem").read())
    cipher = PKCS1_OAEP.new(key)

    # Decrypt the PreMasterSecret
    try:
        start_time = time.time()
        premaster_secret = cipher.decrypt(encrypted_premaster_secret)
        end_time = time.time()
        # Introduce a delay for non-conforming ciphertexts
        if encrypted_premaster_secret[0:2] != b'\x00\x02':
            time.sleep(0.000001)  # Introduce a 1 microsecond delay
        return premaster_secret, end_time - start_time
    except ValueError:
        # This is where the vulnerability lies:
        # - OpenSSL checks the PKCS#1 padding
        # - If padding is incorrect, it raises a ValueError, which can be detected by the attacker
        raise Exception("Decryption error: Invalid PKCS#1 padding") 

# Function to decrypt application data using a dummy AES-CBC implementation
def decrypt_data(data, premaster_secret):
    # Derive the symmetric encryption key from the PreMasterSecret (replace with the actual derivation logic)
    aes_key = sha256(premaster_secret).digest()[:16]

    # Decrypt the data using AES-CBC
    cipher = AES.new(aes_key, AES.MODE_CBC, data[:16])  # Use the first 16 bytes of the data as IV
    decrypted_data = unpad(cipher.decrypt(data[16:]), AES.block_size)
    return decrypted_data

# Function to handle incoming TLS connections
def handle_tls_connection(conn, addr):
    print(f"Connection from {addr}")

    # Wrap the connection with SSL (Server side)
    context = SSL.Context(SSL.TLS_SERVER_METHOD)
    context.use_privatekey_file("private_key.pem")
    context.use_certificate_file("server_cert.pem")

    ssl_conn = SSL.Connection(context, conn)
    ssl_conn.set_accept_state()

    try:
        # Perform the handshake
        ssl_conn.do_handshake()

        # Attempt to receive ClientKeyExchange message and decrypt the PreMasterSecret
        client_key_exchange_data = ssl_conn.recv(1024)
        encrypted_premaster_secret = client_key_exchange_data  # Simplified for illustration
        
        # Attempt to decrypt the PreMasterSecret (this is where the vulnerability lies)
        try:
            premaster_secret, decryption_time = decrypt_premaster_secret_openssl(encrypted_premaster_secret)
            print(f"PreMasterSecret: {premaster_secret}")
            print(f"Decryption Time: {decryption_time}")
        except Exception as e:
            # Log the error (this will be used as a side channel)
            print(f"Error decrypting PreMasterSecret: {e}")

        # Handle HTTP requests
        while True:
            data = ssl_conn.recv(1024)
            if not data:
                break
            
            request = data.decode('utf-8')
            
            # Handle login request
            if "POST /login HTTP/1.1" in request:
                # Extract username and password from the request
                username_data = request.split("username=")[1].split("&")[0]
                password_data = request.split("password=")[1].split("&")[0]
                
                # Check credentials
                if username_data == username and password_data == password:
                    # Successful login
                    response = """HTTP/1.1 200 OK
Content-Type: text/html

<!DOCTYPE html>
<html>
<head>
  <title>Login Successful</title>
</head>
<body>
  <h1>Login Successful!</h1>
</body>
</html>
"""
                    ssl_conn.send(response.encode('utf-8'))
                else:
                    # Failed login
                    response = """HTTP/1.1 401 Unauthorized
Content-Type: text/html

<!DOCTYPE html>
<html>
<head>
  <title>Login Failed</title>
</head>
<body>
  <h1>Login Failed!</h1>
</body>
</html>
"""
                    ssl_conn.send(response.encode('utf-8'))
            else:
                # Handle other requests (you can add more logic here)
                response = """HTTP/1.1 200 OK
Content-Type: text/html

<!DOCTYPE html>
<html>
<head>
  <title>Vulnerable Website</title>
</head>
<body>
  <h1>Welcome to the Vulnerable Website!</h1>
  <form action="/login" method="POST">
    Username: <input type="text" name="username"><br>
    Password: <input type="password" name="password"><br>
    <input type="submit" value="Login">
  </form>
</body>
</html>
"""
                ssl_conn.send(response.encode('utf-8'))

    except SSL.Error as e:
        print(f"SSL error: {e}")
    except Exception as e:
        print(f"Error: {e}")

    # Close the connection
    ssl_conn.close()

# Create a socket and listen for incoming connections
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(('', port))
sock.listen(5)

# Start a new thread to handle each incoming connection
while True:
    conn, addr = sock.accept()
    thread = threading.Thread(target=handle_tls_connection, args=(conn, addr))
    thread.start()
