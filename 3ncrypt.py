import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import os
import base64
import hashlib

SALT = b'some_fixed_salt'
KEY_LENGTH = 32

def derive_key(password: str):
    kdf = Scrypt(
        salt=SALT,
        length=KEY_LENGTH,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path, password, output_path):
    key = derive_key(password)
    iv = os.urandom(16)  # AES block size for IV
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    ciphertext = iv + encryptor.update(plaintext) + encryptor.finalize()
    
    with open(output_path, 'wb') as f:
        f.write(ciphertext)
    
    messagebox.showinfo("Success", f"File encrypted successfully!\n\nOutput File: {output_path}")

def decrypt_file(file_path, password, output_path):
    key = derive_key(password)
    
    with open(file_path, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()
    
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as e:
        messagebox.showerror("Error", "Decryption failed! Incorrect password or corrupted file.")
        return
    
    with open(output_path, 'wb') as f:
        f.write(plaintext)
    
    messagebox.showinfo("Success", f"File decrypted successfully!\n\nOutput File: {output_path}")

# GUI
def main():
    root = tk.Tk()
    root.withdraw()
    
    action = simpledialog.askstring("Action", "Enter 'enc' to encrypt or 'dec' to decrypt:")
    if action not in ("enc", "dec"):
        messagebox.showerror("Error", "Invalid action selected!")
        return

    file_path = filedialog.askopenfilename(title="Select File")
    if not file_path:
        messagebox.showerror("Error", "No file selected!")
        return

    output_path = filedialog.asksaveasfilename(title="Save Output As")
    if not output_path:
        messagebox.showerror("Error", "No output file specified!")
        return

    password = simpledialog.askstring("Password", "Enter password:", show='*')
    if not password:
        messagebox.showerror("Error", "No password entered!")
        return

    if action == "enc":
        encrypt_file(file_path, password, output_path)
    elif action == "dec":
        decrypt_file(file_path, password, output_path)

if __name__ == "__main__":
    main()
