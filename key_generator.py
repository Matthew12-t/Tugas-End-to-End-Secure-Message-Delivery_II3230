from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from pathlib import Path

def generate_keypair(name):
    user_dir = Path("key") / name
    user_dir.mkdir(parents=True, exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    # Simpan private key
    with open(user_dir / f"{name}_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    # Simpan public key
    pub = private_key.public_key()
    with open(user_dir / f"{name}_public.pem", "wb") as f:
        f.write(pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print(f"Key pair untuk {name} berhasil dibuat di folder: {user_dir}")

generate_keypair("alice")
generate_keypair("bob")