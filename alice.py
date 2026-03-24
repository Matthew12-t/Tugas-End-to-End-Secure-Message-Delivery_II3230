import os, json, hashlib, socket
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Load keys 
with open("alice_private.pem", "rb") as f:
    alice_private = serialization.load_pem_private_key(f.read(), password=None)
with open("bob_public.pem", "rb") as f:
    bob_public = serialization.load_pem_public_key(f.read())

# Plaintext
plaintext = "Bob, transfer dana penelitian sebesar 10 juta."
plaintext_bytes = plaintext.encode()
print(f"1. Plaintext: {plaintext}")

# Buat AES Key
aes_key = os.urandom(32)  # 256-bit
iv = os.urandom(16)       # Initialization Vector
print(f"2. AES Key (hex): {aes_key.hex()}")

# Enkripsi pesan dengan AES
cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
encryptor = cipher.encryptor()
pad_len = 16 - (len(plaintext_bytes) % 16)
padded = plaintext_bytes + bytes([pad_len] * pad_len)
ciphertext = encryptor.update(padded) + encryptor.finalize()
print(f"3. Ciphertext (hex): {ciphertext.hex()}")

# Enkripsi AES key dengan public key Bob
encrypted_key = bob_public.encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print(f"4. Encrypted AES Key (hex): {encrypted_key.hex()}")

# Hash plaintext
hash_val = hashlib.sha256(plaintext_bytes).hexdigest()
print(f"5. SHA-256 Hash: {hash_val}")

# Digital Signature
signature = alice_private.sign(
    hash_val.encode(),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
print(f"6. Signature (hex): {signature.hex()}")

# Kirim payload via socket
payload = {
    "source_ip": "127.0.0.1",
    "destination_ip": "127.0.0.1",
    "ciphertext": ciphertext.hex(),
    "iv": iv.hex(),
    "encrypted_key": encrypted_key.hex(),
    "hash": hash_val,
    "signature": signature.hex(),
    "hash_algorithm": "SHA256",
    "symmetric_algorithm": "AES256-CBC",
    "asymmetric_algorithm": "RSA-2048"
}

payload_json = json.dumps(payload).encode()
s = socket.socket()
s.connect(("127.0.0.1", 9999))
s.sendall(payload_json)
s.close()
print("\n7. Payload berhasil dikirim ke Bob!")