from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import os

KEY_FOLDER = "rsa_keys"

def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    os.makedirs(KEY_FOLDER, exist_ok=True)
    with open(f"{KEY_FOLDER}/private_key.pem", "wb") as f:
        f.write(private_key)
    with open(f"{KEY_FOLDER}/public_key.pem", "wb") as f:
        f.write(public_key)

def load_keys():
    with open(f"{KEY_FOLDER}/private_key.pem", "rb") as f:
        private_key = RSA.import_key(f.read())
    with open(f"{KEY_FOLDER}/public_key.pem", "rb") as f:
        public_key = RSA.import_key(f.read())
    return private_key, public_key

def rsa_encrypt(plain_text: str) -> str:
    _, public_key = load_keys()
    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(plain_text.encode())
    return base64.b64encode(encrypted).decode()

def rsa_decrypt(cipher_text: str) -> str:
    private_key, _ = load_keys()
    cipher = PKCS1_OAEP.new(private_key)
    decrypted = cipher.decrypt(base64.b64decode(cipher_text))
    return decrypted.decode()
