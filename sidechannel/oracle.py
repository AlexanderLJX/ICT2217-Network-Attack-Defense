import socketserver
import base64
import time
from settings import *
from aescbc import decrypt

class OracleHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.data = self.request.recv(1024).strip()
        start_time = time.time()
        try:
            encrypted_data = base64.b64decode(self.data)
            decrypted_data = decrypt(encrypted_data, SECRET_KEY)
            self.request.sendall(b'OK')
        except Exception as e:
            self.request.sendall(b'ERROR')
        end_time = time.time()
        print(f"Time taken: {end_time - start_time:.6f} seconds")

if __name__ == "__main__":
    with socketserver.TCPServer((HOST, PORT), OracleHandler) as server:
        server.serve_forever()
