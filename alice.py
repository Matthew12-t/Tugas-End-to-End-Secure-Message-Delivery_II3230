import hashlib
import json
import os
import socket
import textwrap
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Load keys 
with open("key/alice/alice_private.pem", "rb") as f:
    alice_private = serialization.load_pem_private_key(f.read(), password=None)
with open("key/bob/bob_public.pem", "rb") as f:
    bob_public = serialization.load_pem_public_key(f.read())

print("\n=== SISI PENGIRIM (ALICE) ===")
print("Masukkan pesan yang akan dikirim ke Bob:")
plaintext = input("> ")

if len(plaintext.strip()) < 15:
    print("    [!] Catatan: Panjang teks tergolong singkat.")

plaintext_bytes = plaintext.encode()

print("\n[*] 1. Mempersiapkan Data & Kunci")
print(f"    Plaintext          : '{plaintext}'")
aes_key = os.urandom(32)
iv = os.urandom(16)
print("    AES Key (hex)      :\n" + textwrap.fill(aes_key.hex(), width=70, initial_indent="        ", subsequent_indent="        "))

print("\n[*] 2. Melakukan Enkripsi")
cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
encryptor = cipher.encryptor()
pad_len = 16 - (len(plaintext_bytes) % 16)
padded = plaintext_bytes + bytes([pad_len] * pad_len)
ciphertext = encryptor.update(padded) + encryptor.finalize()
print("    Ciphertext (hex)   :\n" + textwrap.fill(ciphertext.hex(), width=70, initial_indent="        ", subsequent_indent="        "))

encrypted_key = bob_public.encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print("    Encrypted Key (hex):\n" + textwrap.fill(encrypted_key.hex(), width=70, initial_indent="        ", subsequent_indent="        "))

print("\n[*] 3. Membuat Hash & Digital Signature")
hash_val = hashlib.sha256(plaintext_bytes).hexdigest()
print("    SHA-256 Hash       :\n" + textwrap.fill(hash_val, width=70, initial_indent="        ", subsequent_indent="        "))

signature = alice_private.sign(
    hash_val.encode(),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
print("    Signature (hex)    :\n" + textwrap.fill(signature.hex(), width=70, initial_indent="        ", subsequent_indent="        "))

# Mengirim payload
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

print("\n[*] 4. Mengirim Payload ke Jaringan")
payload_json = json.dumps(payload).encode()
s = socket.socket()
s.connect(("127.0.0.1", 9999))
s.sendall(payload_json)
s.close()
print("    [+] Payload berhasil dikirim ke Bob!\n")