import hashlib
import json 
import socket
import textwrap
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Load keys
with open("key/bob/bob_private.pem", "rb") as f:
    bob_private = serialization.load_pem_private_key(f.read(), password=None)
with open("key/alice/alice_public.pem", "rb") as f:
    alice_public = serialization.load_pem_public_key(f.read())

print("\n=== SISI PENERIMA (BOB) ===")
print("[*] Menunggu pesan masuk dari alice...")

server = socket.socket()
server.bind(("127.0.0.1", 9999))
server.listen(1)
conn, addr = server.accept()
data = b""
while True:
    chunk = conn.recv(4096)
    if not chunk:
        break
    data += chunk
conn.close()
server.close()

payload = json.loads(data.decode())
print(f"\n[+] Payload diterima dari IP: {payload['source_ip']}")

print("\n[*] 1. Memulai Proses Dekripsi")
dekripsi_kunci_berhasil = False
try:
    encrypted_key = bytes.fromhex(payload["encrypted_key"])
    aes_key = bob_private.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("    [OK] AES Key berhasil didekripsi :\n" + textwrap.fill(aes_key.hex(), width=70, initial_indent="        ", subsequent_indent="        "))
    dekripsi_kunci_berhasil = True
except Exception as e:
    print(f"    [GAGAL] AES Key tidak dapat didekripsi. Detail: {e}")

dekripsi_pesan_berhasil = False
plaintext = ""
if dekripsi_kunci_berhasil:
    try:
        ciphertext = bytes.fromhex(payload["ciphertext"])
        iv = bytes.fromhex(payload["iv"])
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        
        pad_len = padded[-1]
        plaintext = padded[:-pad_len].decode()
        print(f"    [OK] Pesan berhasil didekripsi   : '{plaintext}'")
        dekripsi_pesan_berhasil = True
    except Exception as e:
        print(f"    [GAGAL] Pesan tidak dapat didekripsi. Detail: {e}")
else:
    print("    [LEWATI] Tidak dapat mendekripsi pesan karena kunci AES gagal dibuka.")

print("\n[*] 2. Memulai Proses Verifikasi")
hash_valid = False
if dekripsi_pesan_berhasil:
    hash_local = hashlib.sha256(plaintext.encode()).hexdigest()
    hash_received = payload["hash"]
    if hash_local == hash_received:
        print("    [OK] Verifikasi Hash      : VALID (Pesan tidak berubah)")
        hash_valid = True
    else:
        print("    [GAGAL] Verifikasi Hash   : TIDAK VALID (Pesan mungkin dimodifikasi)")
else:
    print("    [LEWATI] Tidak dapat memverifikasi hash karena pesan gagal didekripsi.")

signature_valid = False
try:
    signature = bytes.fromhex(payload["signature"])
    alice_public.verify(
        signature,
        payload["hash"].encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("    [OK] Verifikasi Signature : VALID (Pesan terbukti dari Alice)")
    signature_valid = True
except Exception as e:
    print(f"    [GAGAL] Verifikasi Signature : TIDAK VALID. Detail: {e}")

print("\n=== KESIMPULAN AKHIR ===")
if dekripsi_pesan_berhasil:
    print(f"Isi Pesan     : '{plaintext}'")
else:
    print("Isi Pesan     : [TIDAK DAPAT DIBACA]")

print(f"Status Data   : {'BERHASIL DIDEKRIPSI' if dekripsi_pesan_berhasil else 'GAGAL DIDEKRIPSI'}")
print(f"Integritas    : {'TERJAGA' if hash_valid else 'TIDAK TERJAGA'}")
print(f"Autentikasi   : {'TERVERIFIKASI (Alice)' if signature_valid else 'TIDAK TERVERIFIKASI'}\n")