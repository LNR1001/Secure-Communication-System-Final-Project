# File: README.md
# Secure Communication System

## Overview
This project simulates a secure communication system between two parties using:
- **RSA** for secure key exchange
- **AES** for encrypting messages
- **HMAC (SHA-256)** for message integrity and authentication

All communication is simulated using local files. There is no socket or network code.

## Technologies
- **Language:** Python 3
- **Library:** pycryptodome

## Setup Instructions

### Optional: Create a Python virtual environment
```bash
python -m venv env
source env/bin/activate  # or .\env\Scripts\activate on Windows
```

### 1. Clone the project and navigate to the directory:
```bash
cd your_project_folder
```

### 2. Install dependencies:
```bash
pip install pycryptodome
```

### 3. Generate RSA keys:
```bash
python keygen.py
```
Generates:
```
keys/
├── sender_private.pem
├── sender_public.pem
├── receiver_private.pem
└── receiver_public.pem
```

### 4. Create a plaintext message:
Create a file called `input_message.txt`:
```
Hello Receiver! This is a secure test.
```

### 5. Encrypt and send the message:
```bash
python sender.py
```
Creates:
```
Transmitted_Data.json
```

### 6. Receive and decrypt the message:
```bash
python receiver.py
```
Expected output:
```
[+] MAC verified: message is authentic
[+] Decrypted Message:
Hello Receiver! This is a secure test.
```

### 7. Freeze dependencies (optional for sharing/reproducibility)
```bash
pip freeze > requirements.txt
```