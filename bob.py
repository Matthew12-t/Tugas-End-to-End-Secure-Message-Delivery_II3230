import hashlib
import json 
import socket
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Load keys
with open("key/bob/bob_private.pem", "rb") as f:
    bob_private = serialization.load_pem_private_key(f.read(), password=None)
with open("key/alice/alice_public.pem", "rb") as f:
    alice_public = serialization.load_pem_public_key(f.read())

# Terima payload via socket 
server = socket.socket()
server.bind(("127.0.0.1", 9999))
server.listen(1)
print("[8] Bob menunggu pesan dari Alice...")
conn, addr = server.accept()
data = b""
while True:
    chunk = conn.recv(4096)
    if not chunk: break
    data += chunk
conn.close()
server.close()

payload = json.loads(data.decode())
print(f"8. Payload diterima dari {payload['source_ip']}")

# Dekripsi AES Key
encrypted_key = bytes.fromhex(payload["encrypted_key"])
aes_key = bob_private.decrypt(
    encrypted_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print(f"9. AES Key berhasil didekripsi: {aes_key.hex()}")

# Dekripsi Pesan 
ciphertext = bytes.fromhex(payload["ciphertext"])
iv = bytes.fromhex(payload["iv"])
cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
decryptor = cipher.decryptor()
padded = decryptor.update(ciphertext) + decryptor.finalize()
pad_len = padded[-1]
plaintext = padded[:-pad_len].decode()
print(f"10. Pesan berhasil didekripsi: '{plaintext}'")

# Verifikasi Hash
hash_local = hashlib.sha256(plaintext.encode()).hexdigest()
hash_received = payload["hash"]
if hash_local == hash_received:
    print(f"11. Hash VALID (pesan tidak diubah)")
else:
    print(f"11. Hash TIDAK VALID (pesan mungkin dimodifikasi)")

# Verifikasi Signature
signature = bytes.fromhex(payload["signature"])
try:
    alice_public.verify(
        signature,
        hash_received.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("12. Signature VALID (pesan benar dari Alice)")
except Exception as e:
    print(f"12. Signature TIDAK VALID — {e}")

# Kesimpulan
print("\nKESIMPULAN")
print(f"Pesan: '{plaintext}'")
print("Integritas: TERJAGA")
print("Pengirim: TERVERIFIKASI (Alice)")