from fpdf import FPDF
from datetime import datetime
import os
import uuid

def generate_pdf(method: str, text: str, result: str) -> str:
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    pdf.cell(200, 10, txt="Şifreleme Raporu", ln=True, align='C')
    pdf.ln(10)
    pdf.cell(200, 10, txt=f"Tarih: {now}", ln=True)
    pdf.cell(200, 10, txt=f"Yöntem: {method}", ln=True)
    pdf.ln(5)
    pdf.multi_cell(0, 10, txt=f"Giriş: {text}")
    pdf.ln(3)
    pdf.multi_cell(0, 10, txt=f"Sonuç: {result}")

    os.makedirs("outputs", exist_ok=True)
    filename = f"outputs/encryption_{uuid.uuid4().hex[:8]}.pdf"
    pdf.output(filename)

    return filename
