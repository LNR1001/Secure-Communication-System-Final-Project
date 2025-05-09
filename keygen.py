# File: keygen.py
from Crypto.PublicKey import RSA
import os

# Create 'keys' directory if it doesn't exist
os.makedirs("keys", exist_ok=True)

# Generate 2048-bit RSA key pairs for both sender and receiver
for role in ["sender", "receiver"]:
    key = RSA.generate(2048)  # Generate RSA key
    private_key = key.export_key()  # Export private key in PEM format
    public_key = key.publickey().export_key()  # Export public key in PEM format

    # Save private and public keys to files
    with open(f"keys/{role}_private.pem", "wb") as prv_file:
        prv_file.write(private_key)
    with open(f"keys/{role}_public.pem", "wb") as pub_file:
        pub_file.write(public_key)

print("[+] RSA keys generated for sender and receiver.")