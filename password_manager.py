import tkinter as tk 
from tkinter import ttk, messagebox, simpledialog
import sqlite3
import base64
import os 
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes 
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pyperclip

DB_NAME = "passwords.db"

def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf=PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key

class PasswordManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("700x500")
        self.root.resizable(False,False)

        self.fernet = None
        self.master_password = None 

        if not os.path.exists(DB_NAME):
            self.create_master_password()
        else:
            self.ask_master_password()

        if self.fernet:
            self.setup_gui()
            self.load_passwords()

    def create_master_password(self):
        master = simpledialog.askstring("Setup","CReate a strong Master Password:", show='*')
        if master and len(master) >= 8:
            salt = os.urandom(16)  
                      
