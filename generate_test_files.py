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

    # 2. Create a dummy PDF
    pdf_content = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\nHello World Test PDF\n%%EOF"
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
