
# 🔐 Kriptoloji Uygulaması

Bu proje, AES, RSA ve SHA256 algoritmaları kullanarak metinleri ve `.txt` dosyalarını şifreleme ve şifre çözme işlemleri yapan bir web uygulamasıdır. Ayrıca şifreleme sonucunu PDF veya TXT formatında indirmenize olanak tanır.

---

## 📦 Kullanılan Teknolojiler

- **Backend:** FastAPI (Python)
- **Frontend:** Next.js (React + Tailwind CSS)
- **Şifreleme:** PyCryptodome (AES, RSA), hashlib (SHA)
- **PDF Oluşturma:** FPDF
- **Dosya Yükleme/İndirme:** FastAPI & Blob + Axios

---

## 🚀 Projenin Çalıştırılması

### ✅ 1. Backend (Sunucu) Başlatma

```bash
cd kriptoloji-python
pip install -r requirements.txt
uvicorn main:app --reload --port 5000
```

### ✅ 2. Frontend (Arayüz) Başlatma

```bash
cd kriptoloji-frontend
npm install
npm run dev
```

> Tarayıcıdan erişim: http://localhost:3000

---

## 🌟 Özellikler

- 🔹 **Metin Şifreleme**
  - 🔒 AES (Simetrik)
  - 🔑 RSA (Asimetrik)
  - 🧩 SHA256 (Geri döndürülemez özetleme)
  - ➕ Kullanıcıdan alınan metin, algoritma ve (varsa) parola ile şifrelenir.

- 🔹 **Metin Şifre Çözme**
  - ✅ AES ve RSA ile şifrelenmiş metinlerin çözümü yapılabilir.
  - ⚠️ SHA geri döndürülemez, sadece doğrulama için kullanılır.

- 🔹 **`.txt` Dosya Şifreleme**
  - Kullanıcı `.txt` dosyasını seçer, içerik okunur ve şifrelenmiş olarak indirilir.

- 🔹 **`.txt` Dosya Şifre Çözme**
  - AES veya RSA ile şifrelenmiş `.txt` dosyasının içeriği çözülür.

- 🔹 **PDF Raporu Oluşturma**
  - Şifreleme yöntemi, orijinal metin, sonuç ve tarih içeren PDF dosyası oluşturulup indirilir.

- 🔹 **Şifreli TXT Dosyası İndirme**
  - Sonuç dosyası `.txt` formatında otomatik indirilir.

---

## 🖼 Uygulama Ekran Görüntüleri

Programın ekran görüntüleri `programfotograf` klasöründe bulunmaktadır.
