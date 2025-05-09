# File: sender.py
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
import json
import os

# Read the message to be sent from a file
with open("input_message.txt", "rb") as f:
    plaintext = f.read()

# Generate a 128-bit AES session key
session_key = get_random_bytes(16)

# Encrypt the plaintext message using AES in EAX mode (provides confidentiality and integrity)
cipher_aes = AES.new(session_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)

# Encrypt the AES session key using the receiver's RSA public key
with open("keys/receiver_public.pem", "rb") as f:
    receiver_pub = RSA.import_key(f.read())
cipher_rsa = PKCS1_OAEP.new(receiver_pub)
encrypted_session_key = cipher_rsa.encrypt(session_key)

# Create HMAC of the ciphertext using SHA-256
h = HMAC.new(session_key, ciphertext, digestmod=SHA256)
mac = h.hexdigest()  # Store MAC as a hex string

# Combine all encrypted data and metadata into a single JSON object
data = {
    "enc_session_key": encrypted_session_key.hex(),  # Encrypted AES key
    "nonce": cipher_aes.nonce.hex(),  # AES nonce
    "ciphertext": ciphertext.hex(),  # Encrypted message
    "tag": tag.hex(),  # AES tag for integrity check
    "mac": mac  # HMAC for message authentication
}

# Write the transmission data to a file
with open("Transmitted_Data.json", "w") as f:
    json.dump(data, f)

print("[+] Message encrypted and written to Transmitted_Data.json")
