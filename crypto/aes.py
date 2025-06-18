from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib

def get_aes_key(password: str) -> bytes:
    return hashlib.sha256(password.encode()).digest()[:16]  # 16-byte key

iv = b"ThisIsAnInitVect"  # يجب أن يكون 16 بايت

def aes_encrypt(plain_text: str, password: str = "default") -> str:
    key = get_aes_key(password)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_text = pad(plain_text.encode(), AES.block_size)
    encrypted = cipher.encrypt(padded_text)
    return base64.b64encode(encrypted).decode()

def aes_decrypt(cipher_text: str, password: str = "default") -> str:
    key = get_aes_key(password)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(base64.b64decode(cipher_text))
    unpadded = unpad(decrypted, AES.block_size)
    return unpadded.decode()
