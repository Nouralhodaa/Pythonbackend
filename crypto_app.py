from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes

import hashlib
import base64
import os

# ====== AES ======
def aes_encrypt(plain_text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plain_text.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + ct_bytes).decode()

def aes_decrypt(cipher_text, key):
    raw = base64.b64decode(cipher_text)
    iv = raw[:16]
    ct = raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()

# ====== SHA256 ======
def sha256_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

# ====== RSA Key Save/Load ======
KEYS_DIR = "rsa_keys"
PRIVATE_KEY_FILE = os.path.join(KEYS_DIR, "private_key.pem")
PUBLIC_KEY_FILE = os.path.join(KEYS_DIR, "public_key.pem")

def generate_and_save_rsa_keys():
    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Save private key
    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Save public key
    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

def load_rsa_keys():
    if not os.path.exists(PRIVATE_KEY_FILE) or not os.path.exists(PUBLIC_KEY_FILE):
        generate_and_save_rsa_keys()

    with open(PRIVATE_KEY_FILE, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    with open(PUBLIC_KEY_FILE, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    return private_key, public_key

# ====== RSA Encryption/Decryption ======
def rsa_encrypt(plain_text, public_key):
    return public_key.encrypt(
        plain_text.encode(),
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def rsa_decrypt(cipher_bytes, private_key):
    return private_key.decrypt(
        cipher_bytes,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    ).decode()

# ====== Example usage ======
if __name__ == "__main__":
    print("=== AES ===")
    key = get_random_bytes(16)
    text = "Merhaba Dünya"
    aes_encrypted = aes_encrypt(text, key)
    print("Encrypted AES:", aes_encrypted)
    print("Decrypted AES:", aes_decrypt(aes_encrypted, key))

    print("\n=== RSA ===")
    priv, pub = load_rsa_keys()
    rsa_encrypted = rsa_encrypt(text, pub)
    print("Encrypted RSA (base64):", base64.b64encode(rsa_encrypted).decode())
    print("Decrypted RSA:", rsa_decrypt(rsa_encrypted, priv))

    print("\n=== SHA256 ===")
    sha = sha256_hash(text)
    print("SHA256 Hash:", sha)
