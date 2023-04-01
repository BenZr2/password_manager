import hashlib
import base64
import tkinter as tk
from cryptography.fernet import Fernet

window = tk.Tk()
window.title("Password Manager")
window.geometry("500x500")

def encrypt_password():
    master_password = master_password_entry.get()
    key = base64.urlsafe_b64encode(bytes(hashlib.sha256(master_password.encode()).digest()))
    fernet = Fernet(key)
    password = password_entry.get().encode()
    encrypted_password = fernet.encrypt(password)

    with open("passwords.txt", "wb") as file:
        file.write(encrypted_password)


def decrypt_password():
    with open("passwords.txt", "rb") as file:
        encrypted_password = file.read()
    
    master_password = master_password_entry.get()
    key = base64.urlsafe_b64encode(bytes(hashlib.sha256(master_password.encode()).digest()))
    fernet = Fernet(key)
    try:
        decrypted_password = fernet.decrypt(encrypted_password)
    except:
        password_label.config(text="Wrong Master Password")
        return
    password_string = decrypted_password.decode()
    password_label.config(text=password_string)


master_password_label = tk.Label(window, text="Enter your master password:")
master_password_label.pack()

master_password_entry = tk.Entry(window, show="*")
master_password_entry.pack()

label = tk.Label(window, text="Enter your password:")
label.pack()

password_entry = tk.Entry(window, show="*")
password_entry.pack()

encrypt_button = tk.Button(window, text="Encrypt Password", command=encrypt_password)
encrypt_button.pack()

decrypt_button = tk.Button(window, text="Decrypt Password", command=decrypt_password)
decrypt_button.pack()

password_label = tk.Label(window)
password_label.pack()

window.mainloop()