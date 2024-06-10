import os, sys, string, random, struct
from base64 import b64encode, b64decode
from hashlib import md5
from Crypto.Cipher import AES
import settings

BLOCK_SIZE = 16

def pad(data):
    length = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([length])*length

def unpad(data):
    return data[:-data[-1]]

def generate_key_iv(password, salt, key_size=32):
    d = d_i = b''
    while len(d) < key_size + BLOCK_SIZE:
        d_i = md5(d_i + password + salt).digest()
        d += d_i
    return d[:key_size], d[key_size:key_size+BLOCK_SIZE]

def encrypt(message, passphrase):
    salt = os.urandom(BLOCK_SIZE - len('Salted__'))
    key, iv = generate_key_iv(passphrase.encode(), salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return b'Salted__' + salt + cipher.encrypt(pad(message.encode()))

def decrypt(encrypted, passphrase):
    print(encrypted)
    encrypted = b64decode(encrypted)
    assert encrypted[0:8] == b'Salted__'
    salt = encrypted[8:16]
    key, iv = generate_key_iv(passphrase.encode(), salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted[16:]))

if __name__ == '__main__':
    sys.argv.append('decrypt')
    sys.argv.append('U2FsdGVkX1/nQBswE9l9e+fqhKQY2DKUm76VIirA9L4=')
    operation = sys.argv[1]
    passphrase = settings.SECRET_KEY
    if operation == 'encrypt':
        message = sys.argv[2]
        print(b64encode(encrypt(message, passphrase)).decode())
    elif operation == 'decrypt':
        encrypted = sys.argv[2]
        print(decrypt(encrypted, passphrase).decode())
    else:
        print("Invalid operation. Use 'encrypt' or 'decrypt'.")
