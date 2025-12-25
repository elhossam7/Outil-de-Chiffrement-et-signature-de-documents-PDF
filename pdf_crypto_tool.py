import tkinter as tk
from tkinter import filedialog, messagebox
import os
import hashlib
from ecdsa import SigningKey, VerifyingKey, NIST256p
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import json

class PDFCryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PDF Crypto Tool (AES + ECDSA)")
        self.root.geometry("600x500")

        self.private_key = None
        self.public_key = None
        self.aes_key = None

        self.create_widgets()

    def create_widgets(self):
        key_frame = tk.LabelFrame(self.root, text="1. Gestion des clés ECDSA", padx=10, pady=10)
        key_frame.pack(fill="x", padx=10, pady=5)

        tk.Button(key_frame, text="Générer une paire de clés", command=self.generate_keys).pack(side=tk.LEFT, padx=5)
        tk.Button(key_frame, text="Charger Clé Publique", command=self.load_public_key).pack(side=tk.LEFT, padx=5)
        tk.Button(key_frame, text="Charger Clé Privée", command=self.load_private_key).pack(side=tk.LEFT, padx=5)
        self.lbl_keys = tk.Label(key_frame, text="Aucune clé chargée", fg="red")
        self.lbl_keys.pack(side=tk.LEFT, padx=10)

        enc_frame = tk.LabelFrame(self.root, text="2. Chiffrement et Signature", padx=10, pady=10)
        enc_frame.pack(fill="x", padx=10, pady=5)

        tk.Button(enc_frame, text="Choisir PDF et Chiffrer/Signer", command=self.encrypt_and_sign).pack(fill="x", padx=5)

        dec_frame = tk.LabelFrame(self.root, text="3. Vérification et Déchiffrement", padx=10, pady=10)
        dec_frame.pack(fill="x", padx=10, pady=5)

        tk.Button(dec_frame, text="Choisir Fichier Chiffré et Vérifier/Déchiffrer", command=self.verify_and_decrypt).pack(fill="x", padx=5)

        self.log_text = tk.Text(self.root, height=10)
        self.log_text.pack(fill="both", expand=True, padx=10, pady=10)

    def log(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)

    def generate_keys(self):
        self.private_key = SigningKey.generate(curve=NIST256p)
        self.public_key = self.private_key.verifying_key
        
        with open("private.pem", "wb") as f:
            f.write(self.private_key.to_pem())
        with open("public.pem", "wb") as f:
            f.write(self.public_key.to_pem())
            
        self.lbl_keys.config(text="Clés générées et sauvegardées", fg="green")
        self.log("Clés ECDSA générées et sauvegardées (private.pem, public.pem).")

    def load_private_key(self):
        file_path = filedialog.askopenfilename(title="Sélectionner la clé privée", filetypes=[("PEM files", "*.pem")])
        if file_path:
            with open(file_path, "rb") as f:
                self.private_key = SigningKey.from_pem(f.read())
            self.log("Clé privée chargée.")
            if self.public_key:
                 self.lbl_keys.config(text="Paire de clés prête", fg="green")

    def load_public_key(self):
        file_path = filedialog.askopenfilename(title="Sélectionner la clé publique", filetypes=[("PEM files", "*.pem")])
        if file_path:
            with open(file_path, "rb") as f:
                self.public_key = VerifyingKey.from_pem(f.read())
            self.log("Clé publique chargée.")
            if self.private_key:
                 self.lbl_keys.config(text="Paire de clés prête", fg="green")
            else:
                 self.lbl_keys.config(text="Clé publique chargée", fg="blue")

    def encrypt_and_sign(self):
        if not self.private_key:
            messagebox.showerror("Erreur", "Veuillez d'abord générer ou charger une clé privée.")
            return

        file_path = filedialog.askopenfilename(title="Sélectionner un PDF", filetypes=[("PDF files", "*.pdf")])
        if not file_path:
            return

        try:
            with open(file_path, "rb") as f:
                plaintext = f.read()

            aes_key = get_random_bytes(32) 
            iv = get_random_bytes(16)
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
            
            encrypted_content = iv + ciphertext

            key_file = file_path + ".aeskey"
            with open(key_file, "wb") as f:
                f.write(aes_key)
            self.log(f"Clé AES sauvegardée dans : {os.path.basename(key_file)}")

            file_hash = hashlib.sha256(encrypted_content).digest()

            signature = self.private_key.sign(file_hash)

            enc_file_path = file_path + ".enc"
            with open(enc_file_path, "wb") as f:
                f.write(encrypted_content)
            
            sig_file_path = file_path + ".sig"
            with open(sig_file_path, "wb") as f:
                f.write(signature)

            self.log(f"Fichier chiffré : {os.path.basename(enc_file_path)}")
            self.log(f"Signature : {os.path.basename(sig_file_path)}")
            messagebox.showinfo("Succès", "Fichier chiffré et signé avec succès.")

        except Exception as e:
            messagebox.showerror("Erreur", str(e))
            self.log(f"Erreur: {str(e)}")

    def verify_and_decrypt(self):
        if not self.public_key:
            messagebox.showerror("Erreur", "Veuillez d'abord générer ou charger une clé publique.")
            return

        enc_file_path = filedialog.askopenfilename(title="Sélectionner le fichier chiffré (.enc)", filetypes=[("Encrypted files", "*.enc")])
        if not enc_file_path:
            return

        base_path = enc_file_path.replace(".enc", "")
        sig_file_path = base_path + ".sig"
        
        if not os.path.exists(sig_file_path):
            sig_file_path = filedialog.askopenfilename(title="Sélectionner le fichier de signature (.sig)", filetypes=[("Signature files", "*.sig")])
            if not sig_file_path: return

        key_file_path = base_path + ".aeskey"
        
        if not os.path.exists(key_file_path):
            key_file_path = filedialog.askopenfilename(title="Sélectionner la clé AES (.aeskey)", filetypes=[("Key files", "*.aeskey")])
            if not key_file_path: return

        try:
            with open(enc_file_path, "rb") as f:
                encrypted_content = f.read()
            
            iv = encrypted_content[:16]
            ciphertext = encrypted_content[16:]

            with open(sig_file_path, "rb") as f:
                signature = f.read()

            file_hash = hashlib.sha256(encrypted_content).digest()
            try:
                if self.public_key.verify(signature, file_hash):
                    self.log("Signature VALIDE.")
                else:
                    self.log("Signature INVALIDE.")
                    messagebox.showerror("Erreur", "Signature invalide ! Le fichier a peut-être été modifié.")
                    return
            except Exception as e:
                self.log(f"Echec de vérification de signature: {e}")
                messagebox.showerror("Erreur", "Signature invalide !")
                return

            with open(key_file_path, "rb") as f:
                aes_key = f.read()

            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

            dec_file_path = base_path + "_decrypted.pdf"
            with open(dec_file_path, "wb") as f:
                f.write(plaintext)

            self.log(f"Fichier déchiffré sauvegardé : {os.path.basename(dec_file_path)}")
            messagebox.showinfo("Succès", f"Signature valide.\nFichier déchiffré : {os.path.basename(dec_file_path)}")

        except Exception as e:
            messagebox.showerror("Erreur", str(e))
            self.log(f"Erreur: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PDFCryptoApp(root)
    root.mainloop()
