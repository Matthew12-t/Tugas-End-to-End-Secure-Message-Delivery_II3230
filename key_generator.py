from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_keypair(name):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    # Simpan private key
    with open(f"{name}_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    # Simpan public key
    pub = private_key.public_key()
    with open(f"{name}_public.pem", "wb") as f:
        f.write(pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print(f"Key pair untuk {name} berhasil dibuat!")

generate_keypair("alice")
generate_keypair("bob")