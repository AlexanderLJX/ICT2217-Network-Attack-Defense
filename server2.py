from flask import Flask, request, render_template_string, make_response
import time
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

# Create Flask app
app = Flask(__name__)

# Simple form template for login
form_template = '''
<!doctype html>
<title>Login</title>
<h1>Login</h1>
<form method=post action="/login">
  <label for="username">Username:</label>
  <input type="text" id="username" name="username"><br><br>
  <label for="password">Password:</label>
  <input type="password" id="password" name="password"><br><br>
  <input type="submit" value="Submit">
</form>
'''

# Generate RSA keys
private_key = crypto_rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Export the public key to send to clients
pem_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Simulated password storage
valid_credentials = {
    "admin": "password123"
}

# Vulnerable login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        encrypted_password = request.form['password'].encode('latin1')

        try:
            # Decrypt the password
            password = private_key.decrypt(
                encrypted_password,
                padding.PKCS1v15()
            ).decode('utf-8')

            # Simulate a timing leak
            if username in valid_credentials and valid_credentials[username] == password:
                time.sleep(0.1)  # Correct password delay
                return "Login successful"
            else:
                time.sleep(0.2)  # Incorrect password delay
                return "Login failed"
        except ValueError:
            # Simulate different timing for padding error
            time.sleep(0.3)
            return "Login failed"
    return render_template_string(form_template)

# Route to get the public key
@app.route('/public_key')
def get_public_key():
    response = make_response(pem_public_key)
    response.headers['Content-Type'] = 'application/x-pem-file'
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=443, ssl_context='adhoc')
