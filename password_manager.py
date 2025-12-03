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
            key = derive_key(master, salt)
            self.fernet = Fernet(key)

            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            c.execute('''CREATE TABLE vault(
                      id INTEGER PRIMARY KEY
                      website TEXT ONT NULL,
                      username TEXT,
                      password TEXT NOT NULL,
                      notes TEXT
                      )''')
            c.execute(" CREATE TABLE master (salt BLOB)")
            c.execute("INSERT INTO master (salt) VALUES (?)", (salt,))
            conn.commit()
            conn.close()
            messagebox.showinfo("Success", "Password Manager Created")
            self.setup_gui()
        else:
            messagebox.showerror("Error", "Master Password must be at least 8+ characters")
            self.root.quit()

    def ask_master_password(self):
        master = simpledialog.askstring("Login", "Enter master Password:",show='*')
        if not master :
            self.root.quit()
            return
        
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT salt FROM master")
        row = c.fetchone()
        conn.close()

        if row :
            salt = row[0]
            key = derive_key(master, salt)
            try :
                self.fernet = Fernet(key)
                # test decryption with dummy datat if needed 
                self.master_password = master 
                return
            except :
                messagebox.showerror("Error", "Invalid Master Password")
                self.ask_master_password()
        else:
            messagebox.showerror("Error", "database corrupted")
            self.root.quit()

    def setup_gui(self):
        #search bar 
        search_frame = tk.Frame(self.root)
        search_frame.pack(pady=10, fill=tk.X, padx=20)

        tk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        search_entry = tk.Entry(search_frame, textvariable= self.search_var, width=40)
        search_entry.pack(side=tk.LEFT, padx=5)
        search_entry.bind('<KeyRelease>', lambda e: self.load_passwords())

        # buttons
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=5)

        tk.Button(btn_frame, text="Add New", command=self.add_entry, bg=)
