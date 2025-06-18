from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from crypto.aes import aes_encrypt, aes_decrypt
from crypto.rsa import rsa_encrypt, rsa_decrypt
from crypto.sha import sha256_hash
import os
from fastapi.responses import FileResponse
import uuid
from utils.pdf_generator import generate_pdf
from fastapi.responses import FileResponse
from fastapi import FastAPI, UploadFile, File, HTTPException
import shutil
from fastapi.middleware.cors import CORSMiddleware



app = FastAPI()

class TextData(BaseModel):
    text: str
    method: str
    password: str | None = None 

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/encrypt")
def encrypt(data: TextData):
    try:
        if data.method == "AES":
          result = aes_encrypt(data.text, data.password or "default")

        elif data.method == "RSA":
            result = rsa_encrypt(data.text)
        elif data.method == "SHA":
            result = sha256_hash(data.text)
        else:
            raise ValueError("Yöntem geçersiz")
        return {"result": result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/download")
def download_file(data: TextData):
    try:
        if data.method == "AES":
            result = aes_encrypt(data.text)
        elif data.method == "RSA":
            result = rsa_encrypt(data.text)
        elif data.method == "SHA":
            result = sha256_hash(data.text)
        else:
            raise ValueError("Yöntem geçersiz")

        os.makedirs("outputs", exist_ok=True)
        filename = f"outputs/output_{uuid.uuid4().hex[:8]}.txt"

        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"Yöntem: {data.method}\n")
            f.write(f"Giriş: {data.text}\n")
            f.write(f"Sonuç: {result}\n")

        return FileResponse(path=filename, filename=os.path.basename(filename), media_type='text/plain')

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    
@app.post("/pdf")
def get_pdf(data: TextData):
    try:
        if data.method == "AES":
            result = aes_encrypt(data.text, data.password or "default")
        elif data.method == "RSA":
            result = rsa_encrypt(data.text)
        elif data.method == "SHA":
            result = sha256_hash(data.text)
        else:
            raise ValueError("Yöntem geçersiz")

        file_path = generate_pdf(data.method, data.text, result)
        return FileResponse(path=file_path, filename=os.path.basename(file_path), media_type='application/pdf')

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    
@app.post("/decrypt")
def decrypt(data: TextData):
    try:
        if data.method == "AES":
            if not data.password:
                raise ValueError("AES şifre çözme için parola gerekli.")
            result = aes_decrypt(data.text, data.password)
        elif data.method == "RSA":
            result = rsa_decrypt(data.text)
        else:
            raise ValueError("Yöntem sadece AES veya RSA olmalı")
        return {"result": result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/encrypt-file")
async def encrypt_file(method: str = "AES", password: str = "default", file: UploadFile = File(...)):
    try:
        contents = await file.read()
        text = contents.decode("utf-8")

        if method == "AES":
            result = aes_encrypt(text, password)
        elif method == "RSA":
            result = rsa_encrypt(text)
        else:
            raise ValueError("Desteklenmeyen yöntem")

        os.makedirs("outputs", exist_ok=True)
        output_path = f"outputs/encrypted_{uuid.uuid4().hex[:8]}.txt"
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(result)

        return FileResponse(path=output_path, filename=os.path.basename(output_path), media_type='text/plain')

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/decrypt-file")
async def decrypt_file(method: str = "AES", password: str = "default", file: UploadFile = File(...)):
    try:
        contents = await file.read()
        encrypted_text = contents.decode("utf-8")

        if method == "AES":
            result = aes_decrypt(encrypted_text, password)
        elif method == "RSA":
            result = rsa_decrypt(encrypted_text)
        else:
            raise ValueError("Desteklenmeyen yöntem")

        os.makedirs("outputs", exist_ok=True)
        output_path = f"outputs/decrypted_{uuid.uuid4().hex[:8]}.txt"
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(result)

        return FileResponse(path=output_path, filename=os.path.basename(output_path), media_type='text/plain')

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/decrypt-file-pdf")
async def decrypt_file_pdf(method: str = "AES", password: str = "default", file: UploadFile = File(...)):
    try:
        contents = await file.read()
        encrypted_text = contents.decode("utf-8")

        if method == "AES":
            result = aes_decrypt(encrypted_text, password)
        elif method == "RSA":
            result = rsa_decrypt(encrypted_text)
        else:
            raise ValueError("Desteklenmeyen yöntem")

        # PDF dosyasını oluştur
        file_path = generate_pdf(method, encrypted_text, result)
        return FileResponse(path=file_path, filename=os.path.basename(file_path), media_type='application/pdf')

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
