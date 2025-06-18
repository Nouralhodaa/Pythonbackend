import hashlib

def sha256_hash(text: str) -> str:
    sha = hashlib.sha256()
    sha.update(text.encode())
    return sha.hexdigest()
