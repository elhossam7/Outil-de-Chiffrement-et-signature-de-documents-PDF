import os
import hashlib
from ecdsa import SigningKey, NIST256p
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

def generate_test_files():
    print("Generating test files...")
    
    # 1. Generate Keys
    private_key = SigningKey.generate(curve=NIST256p)
    public_key = private_key.verifying_key
    
    with open("test_public.pem", "wb") as f:
        f.write(public_key.to_pem())
    print("Generated test_public.pem")

    # 2. Create a valid minimal PDF
    pdf_content = (
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<< /Type /Catalog /Pages 2 0 R >>\n"
        b"endobj\n"
        b"2 0 obj\n"
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n"
        b"endobj\n"
        b"3 0 obj\n"
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\n"
        b"endobj\n"
        b"4 0 obj\n"
        b"<< /Type /Font /Subtype /Type1 /Name /F1 /BaseFont /Helvetica >>\n"
        b"endobj\n"
        b"5 0 obj\n"
        b"<< /Length 44 >>\n"
        b"stream\n"
        b"BT /F1 24 Tf 100 700 Td (Hello World) Tj ET\n"
        b"endstream\n"
        b"endobj\n"
        b"xref\n"
        b"0 6\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000058 00000 n \n"
        b"0000000115 00000 n \n"
        b"0000000243 00000 n \n"
        b"0000000323 00000 n \n"
        b"trailer\n"
        b"<< /Size 6 /Root 1 0 R >>\n"
        b"startxref\n"
        b"418\n"
        b"%%EOF"
    )
    # We won't save the original PDF to disk to avoid confusion, we just encrypt this content.
    
    # 3. Encrypt with AES
    aes_key = get_random_bytes(32) # AES-256
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(pdf_content, AES.block_size))
    
    encrypted_content = iv + ciphertext

    # Save AES Key
    with open("test_sample.pdf.aeskey", "wb") as f:
        f.write(aes_key)
    print("Generated test_sample.pdf.aeskey")

    # 4. Sign
    file_hash = hashlib.sha256(encrypted_content).digest()
    signature = private_key.sign(file_hash)
    
    with open("test_sample.pdf.sig", "wb") as f:
        f.write(signature)
    print("Generated test_sample.pdf.sig")

    # 5. Save Encrypted File
    with open("test_sample.pdf.enc", "wb") as f:
        f.write(encrypted_content)
    print("Generated test_sample.pdf.enc")
    
    print("Done. You can now use the tool to decrypt 'test_sample.pdf.enc' using 'test_public.pem'.")

if __name__ == "__main__":
    generate_test_files()
