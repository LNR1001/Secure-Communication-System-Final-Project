# File: receiver.py
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
import json

# Load the encrypted data from the transmission file
with open("Transmitted_Data.json", "r") as f:
    data = json.load(f)

# Convert hex-encoded data back to bytes
enc_session_key = bytes.fromhex(data["enc_session_key"])
nonce = bytes.fromhex(data["nonce"])
ciphertext = bytes.fromhex(data["ciphertext"])
tag = bytes.fromhex(data["tag"])
mac = data["mac"]

# Decrypt the AES session key using the receiver's RSA private key
with open("keys/receiver_private.pem", "rb") as f:
    receiver_priv = RSA.import_key(f.read())
cipher_rsa = PKCS1_OAEP.new(receiver_priv)
session_key = cipher_rsa.decrypt(enc_session_key)

# Verify HMAC to ensure message integrity
try:
    h = HMAC.new(session_key, ciphertext, digestmod=SHA256)
    h.verify(bytes.fromhex(mac))
    print("[+] MAC verified: message is authentic")
except ValueError:
    print("[-] MAC verification failed!")
    exit()

# Decrypt the message using AES in EAX mode
cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)

# Display the original message
print("[+] Decrypted Message:")
print(plaintext.decode())

