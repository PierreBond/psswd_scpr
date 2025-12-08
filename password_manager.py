import tkinter as tk 
from tkinter import ttk, messagebox, simpledialog
import sqlite3
import base64
import os 
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes 
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pyperclip
from typing import Optional
import pyotp
import pyqrcode
import tempfile
import re
from tkinter import PhotoImage
import time 
import hashlib

DB_NAME = "passwords.db"
MAX_LOGIN_ATTEMPTS =5 
LOCKOUT_TIME = 300


def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf=PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key

def validate_password_strength(password: str) -> tuple[bool, str]:
    # validates password meets security requirments
    if len(password) < 12:
        return False , "Password must be atleast 12 characters "
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain UPPERCASE letters"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain lowercase letters"
    if not re.search(r'[!@#$%^&*()<>,.?/;":{}~|_-`~]', password):
        return False, "Password must contain special characters"
    return True, "Password is strong"

class PasswordManager:
    def __init__(self, root):
        self.root = root
        self.root.title(" SecurePassword Manager")
        self.root.geometry("800x600")
        self.root.resizable(False,False)

        # self.fernet = None
        self.fernet: Optional[Fernet] = None
        self.master_password: Optional[str] = None 
        self.search_var = None
        self.tree = None
        self.menu = None
        self.login_attempts = 0
        self.last_failed_attempt = 0

        if not os.path.exists(DB_NAME):
            self.create_master_password()
        else:
            self.ask_master_password()

        if self.fernet:
            self.setup_gui()
            self.load_passwords()

    def create_master_password(self):
        master = simpledialog.askstring("Setup","Create a strong Master Password:\n(12+ chars, uppecase, lowercase, number, symbol)", show='*')
        if not master:
            self.root.quit()
            return

        is_valid, message =validate_password_strength(master)
        if  not is_valid:
            messagebox.showerror("Weak Password", message)
            self.root.quit()
            return


        confirm = simpledialog.askstring("Confirm ", "Re-enter Master Password:", show='*')
        if master != confirm:
            messagebox.showerror("Error", "Password does not match")
            self.root.quit()
            return
            
        #Generate TOTP secret
        totp_secret = pyotp.random_base32()
        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
            name="LocalPasswordManager",
            issuer_name="MyPasswordManager"
        )

        #Create QR code 
        qr = pyqrcode.create(totp_uri)
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
            qr.png(tmp.name, scale=6)
            qr_path = tmp.name

        # Show QR code
        qr_window = tk.Toplevel(self.root)
        qr_window.title("Scan with Aithenticator App")
        qr_window.geometry("300x350")

        img = PhotoImage(file=qr_path)
        label = tk.Label(qr_window, image=img)
        label.image= img #keep reference
        label.pack(pady=10)

        tk.Label(qr_window, text="Scan this QR code with your\n Authenticator App",
                    justify=tk.CENTER, font=("Arial", 10), wraplength=300).pack(pady=10)
        tk.Label(qr_window, text=f"or enter manually:\n{totp_secret}",
                    font=("Courier",9), bg="#f0f0f0", relief=tk.SOLID, padx=10, pady=10).pack(pady=10)
        
        def verify_2fa():
            code = simpledialog.askstring("2FA Required", "Enter the 6-digit code from your app:",parent=qr_window)
            if code and pyotp.TOTP(totp_secret).verify(code, valid_window=1):
                try:
                    os.unlink(qr_path)
                except:
                    qr_window.destroy()

                # save master password + encrypted TOTP secret
                salt = os.urandom(16)
                key = derive_key(master, salt)
                self.fernet = Fernet(key)
                self.master_password = master
                encrypted_totp = self.fernet.encrypt(totp_secret.encode()).decode()

                conn = sqlite3.connect(DB_NAME)
                c = conn.cursor()
                c.execute('''CREATE TABLE IF NOT EXISTS vault(
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            website TEXT NOT NULL,
                            username TEXT,
                            password TEXT NOT NULL,
                            notes TEXT,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                            )''')
                c.execute('''CREATE TABLE IF NOT EXISTS master (id INTEGER PRIMARY KEY, salt BLOB NOT NULL, totp_secret TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
                c.execute("INSERT INTO master (salt, totp_secret) VALUES (?, ?)", (salt, encrypted_totp))
                conn.commit()
                conn.close()

                messagebox.showinfo("Success", "Password Manager Created with 2FA")
                self.setup_gui()
                self.load_passwords()
        
            else:
                messagebox.showerror("Error", "Master Password must be at least 8+ characters")
                # self.root.quit()
        tk.Button(qr_window, text="Ive Scanned , Enter Code", command=verify_2fa, bg="#4CAF50", fg="white", font=("Arial", 11, "bold")).pack(pady=15)


        def cleanup_and_quit(self, window, qr_path):
            try:
                os.unlink(qr_path)
            except:
                pass
            window.destoy()
            self.root.quit()


    def ask_master_password(self):
        if self.login_attempts >= MAX_LOGIN_ATTEMPTS:
            time_since_last = time.time() - self.last_failed_attempt

            if  time_since_last < LOCKOUT_TIME:
                remaining =  int(LOCKOUT_TIME - time_since_last)
                messagebox.showerror("Locked Out", f"Too many failed attempts. Try again in {remaining} seconds.")
                self.root.quit()
                return
            else:
                self.login_attempts = 0


        master = simpledialog.askstring("Login", "Enter master Password:",show='*')
        if not master :
            self.root.quit()
            return
        
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT salt, totp_secret FROM master")
        row = c.fetchone()
        conn.close()

        if not row :
            messagebox.showerror("Error", "database corrupted")
            self.root.quit()
            return
        
        salt , encrypted_totp= row
        key = derive_key(master, salt)

        try :
            temp_fernet = Fernet(key)
            totp_secret = temp_fernet.decrypt(encrypted_totp.encode()).decode()
            
        except Exception as e:
            self.login_attempts +=1
            self.last_failed_attempt = time.time()
            remaining = MAX_LOGIN_ATTEMPTS - self.login_attempts
            messagebox.showerror("Authentication Failed", f"Invalid Credentials. {remaining} attempts remaining")
            if self.login_attempts < MAX_LOGIN_ATTEMPTS:
                self.ask_master_password()
            else:
                self.root.quit()
            return
        
        # ask for 2fa
        code = simpledialog.askstring("2FA Required", "Enter 6-digit code from Authenticator app:", show='*')
        if code and pyotp.TOTP(totp_secret).verify(code):
            self.master_password = master 
            self.setup_gui()
            self.load_passwords()

        else:
            messagebox.showerror("Access Denied", "Invalid 2FA code")
            self.ask_master_password()    


        # else:
        #     messagebox.showerror("Error", "database corrupted")
        #     self.root.quit()

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

        tk.Button(btn_frame, text="Add New", command=self.add_entry, bg="#4CAF50" , fg="white", width=12).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Refresh", command=self.load_passwords, bg="#2196F3" , fg="white", width=12).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Exit", command=self.root.quit, bg="#f44336" , fg="white", width=12).pack(side=tk.LEFT, padx=5)

        # treeview
        columns = ("website", "username", "password", "notes")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings")
        self.tree.pack(padx=2, pady=10, fill=tk.BOTH, expand=True)

        self.tree.heading("website", text= "Website/Service")
        self.tree.heading("username", text= "Username/Email")
        self.tree.heading("Password", text= "Password")
        self.tree.heading("notes", text= "Notes")

        self.tree.column("website", width=180)
        self.tree.column("username", width=160)
        self.tree.column("password", width=120, anchor=tk.CENTER)
        self.tree.column("notes", width=150)

        # right click menu 
        self.menu = tk.Menu(self.root, tearoff=0)
        self.menu.add_command(label = "copy password", command= self.copy_password)
        self.menu.add_command(label = "edit", command= self.edit_entry)
        self.menu.add_command(label = "delete", command= self.delete_entry)
        self.tree.bind("<Button-3>", self.show_context_menu)

    def encrypt(self, text):
        if self.fernet is None:
            raise ValueError("Master password not unlocked")
        return self.fernet.encrypt(text.encode()).decode()
    
    def decrypt(self, token):
        if self.fernet is None:
            raise ValueError("Master password not unlocked")
        return self.fernet.decrypt(token.encode()).decode()
    def load_passwords(self):
        for items in self.tree.get_children():
            self.tree.delete(items)

        search_item = self.search_var.get()

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT id , website, username, password, notes FROM vault")
        rows = c.fetchall()

        for row in rows:
            id_, website, username, enc_pass, notes = row 
            try:
                password = self.decrypt(enc_pass)
            except:
                password = "Decryption Error"

            website_lower =website.lower()  
            username_lower = "" if not username else username.lower()

            if search_item in website_lower or search_item in username_lower:
                self.tree.insert("", tk.END, values=(website, username or "","••••••••", notes or ""), tags=(id_))


        conn.close()

    def add_entry(self):
        self.show_entry_dailog()

    def edit_entry(self):
        selected = self.tree.selection()
        if not selected :
            messagebox.showwarning("Select","Please select an entry to edit") 
            return                
        item = self.tree.item(selected[0])
        entry_id = item['tags'][0]
        values = item['values']

        self.show_entry_dailog(edit_mode=True, entry_id = entry_id, current = values)

    def show_entry_dailog(self, edit_mode= False, entry_id=None, current = None):
        dailog = tk.Toplevel(self.root)
        dailog.title("Edit Entry" if edit_mode else "Add New Entry")
        dailog.geometry("400x300")
        dailog.transient(self.root)
        dailog.grab_set()

        tk.Label(dailog, text="Website/Service:").pack(pady=5)
        website_entry = tk.Entry(dailog, width=50)
        website_entry.pack(pady=5)

        tk.Label(dailog, text="Username/Email:").pack(pady=5)
        username_entry = tk.Entry(dailog, width=50)
        username_entry.pack(pady=5)

        tk.Label(dailog, text="Paswword:").pack(pady=5)
        password_entry = tk.Entry(dailog, width=50)
        password_entry.pack(pady=5)

        tk.Label(dailog, text="Notes(optional):").pack(pady=5)
        notes_entry = tk.Entry(dailog, width=50)
        notes_entry.pack(pady=5)

        tk.Button(dailog, text="Generate Strong Password",
                  command=lambda: password_entry.insert(0, os.urandom(16).hex())).pack(pady=5)
        
        if edit_mode and current:
            website_entry.insert(0, current[0])
            username_entry.insert(0, current[1] if current[1] != "" else "")
            notes_entry.insert(0, current[3] if current[3] else "")
            
        def save():
            website = website_entry.get().strip()
            username =  username_entry.get().strip()
            password =  password_entry.get().strip()
            notes = notes_entry.get().strip()

            if not website or not password:
                messagebox.showerror("Error", "Website amd Password are required")
                return
            enc_password =  self.encrypt(password)

            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()

            if edit_mode:
                c.execute("UPDATE vault SET website=?, username=?, password=?, notes=? WHERE id=?",
                          (website, username,password, notes, entry_id))
            else:
                 c.execute("INSERT INTO vault (website, username,password, notes) VALUES (?, ?, ?, ?)",
                          (website, username,password, notes, entry_id))  
            conn.commit()
            conn.close()

            dailog.destroy()
            self.load_passwords()

        tk.Button(dailog, text="Save", command= save, bg="#4CAF50",fg="white").pack(pady=10)

    def delete_entry(self):
        selected = self.tree.selection()
        if not selected:
            return
        if messagebox.askyesno("Delete", "Delete this entry permanently?"):
            entry_id = self.tree.item(selected[0])['tags'][0]
            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            c.execute("DELETE FROM vault WHERE id=?", (entry_id,))
            conn.commit()
            conn.close()
            self.load_passwords()

    def copy_password(self):
        selected = self.tree.selection()
        if not selected:
            return
        entry_id = self.tree.item(selected[0])['tags'][0]

        conn =sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT password FROM vault WHERE id=?", (entry_id,))
        enc_pass = c.fetchone()[0]
        conn.close()

        try:
            password =  self.decrypt(enc_pass)
            pyperclip.copy(password)
            messagebox.showinfo("Copied", "Password copied to clipboard")
        except:
            messagebox.showerror("Error", "Failed to decrypt password")

    def show_context_menu(self, event):
            try:
                self.menu.tk_popup(event.x_root, event.y_root)
            finally:
                self.menu.grab_release()


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()
