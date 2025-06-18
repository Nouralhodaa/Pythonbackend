import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from crypto_app import (
    aes_encrypt, aes_decrypt,
    rsa_encrypt, rsa_decrypt,
    sha256_hash,
    load_rsa_keys, generate_and_save_rsa_keys
)
from Crypto.Random import get_random_bytes
import base64

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Kriptoloji Uygulaması")
        self.root.geometry("700x550")

        self.private_key, self.public_key = load_rsa_keys()
        self.aes_key = get_random_bytes(16)

        # Giriş alanı
        self.input_label = tk.Label(root, text="Metin:")
        self.input_label.pack()
        self.input_entry = tk.Text(root, height=5, width=80)
        self.input_entry.pack(pady=5)

        # İşlem seçici
        self.option = ttk.Combobox(root, values=[
            "AES - Şifrele", "AES - Çöz",
            "RSA - Şifrele", "RSA - Çöz",
            "SHA256 - Özetle"
        ])
        self.option.set("AES - Şifrele")
        self.option.pack(pady=10)

        # Düğmeler
        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=5)

        self.run_button = tk.Button(btn_frame, text="İşlemi Uygula", command=self.process)
        self.run_button.grid(row=0, column=0, padx=5)

        self.keygen_button = tk.Button(btn_frame, text="Yeni RSA Anahtarı Oluştur", command=self.generate_keys)
        self.keygen_button.grid(row=0, column=1, padx=5)

        self.load_file_button = tk.Button(btn_frame, text="Dosya Yükle", command=self.load_file)
        self.load_file_button.grid(row=0, column=2, padx=5)

        # Çıktı
        self.output_label = tk.Label(root, text="Sonuç:")
        self.output_label.pack()
        self.output_text = tk.Text(root, height=6, width=80, state="disabled")
        self.output_text.pack(pady=5)

    def process(self):
        operation = self.option.get()
        input_text = self.input_entry.get("1.0", tk.END).strip()

        if not input_text:
            messagebox.showwarning("Uyarı", "Lütfen metin girin!")
            return

        try:
            if operation == "AES - Şifrele":
                result = aes_encrypt(input_text, self.aes_key)

            elif operation == "AES - Çöz":
                result = aes_decrypt(input_text, self.aes_key)

            elif operation == "RSA - Şifrele":
                encrypted = rsa_encrypt(input_text, self.public_key)
                result = base64.b64encode(encrypted).decode()

            elif operation == "RSA - Çöz":
                encrypted = base64.b64decode(input_text)
                result = rsa_decrypt(encrypted, self.private_key)

            elif operation == "SHA256 - Özetle":
                result = sha256_hash(input_text)

            self.output_text.configure(state="normal")
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, result)
            self.output_text.configure(state="disabled")

        except Exception as e:
            messagebox.showerror("Hata", f"Bir hata oluştu:\n{str(e)}")

    def generate_keys(self):
        generate_and_save_rsa_keys()
        self.private_key, self.public_key = load_rsa_keys()
        messagebox.showinfo("Başarılı", "Yeni RSA anahtarları oluşturuldu ve kaydedildi.")

    def load_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    self.input_entry.delete("1.0", tk.END)
                    self.input_entry.insert(tk.END, content)
            except Exception as e:
                messagebox.showerror("Dosya Hatası", f"Dosya okunamadı:\n{str(e)}")

# Programı başlat
if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
