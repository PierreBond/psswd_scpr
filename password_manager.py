import tkinter as tk 
from tkinter import ttk, messagebox, simpledialog
import sqlite3
import base64
from base64 import urlsafe_b64encode, urlsafe_b64decode
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
# from argon2 import PasswordHasher 
from argon2.low_level import hash_secret_raw, Type

DB_NAME = "passwords.db"
MAX_LOGIN_ATTEMPTS =5 
LOCKOUT_TIME = 300

#used argon cos why not 
def derive_key( master_password: str, salt: bytes) -> bytes:
    if salt is None :
        salt = os.urandom(16)

    raw_key = hash_secret_raw(
        secret= master_password.encode(),
        salt =salt,
        time_cost = 3,
        memory_cost= 65536,
        parallelism = 4, 
        hash_len =32,
        type = Type.ID

    )
    key = urlsafe_b64encode(raw_key)
    return key

# def derive_key(master_password: str, salt: bytes) -> bytes:
#     ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32)
#     hash_bytes = ph.hash(master_password.encode(), salt = salt)

#     key = base64.urlsafe_b64encode(hash_bytes.encode().split(b'$')[-1][:32])
#     return key

# def derive_key(master_password: str, salt: bytes) -> bytes:
#     kdf=PBKDF2HMAC(
#         algorithm=hashes.SHA256(),
#         length=32,
#         salt=salt,
#         iterations=480000,
#     )
#     key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
#     return key

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
        qr_window.title("Scan with Authenticator App")
        qr_window.geometry("600x650")

        img = PhotoImage(file=qr_path)
        label = tk.Label(qr_window, image=img)
        setattr(label, "imge", img)
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
            self.fernet = temp_fernet
            self.master_password = master
            self.login_attempts = 0 #resset on success

        else:
            self.login_attempts += 1
            self.last_failed_attempt = time.time()
            remaining = MAX_LOGIN_ATTEMPTS - self.login_attempts
            messagebox.showerror("Authentication Failed ", f"Invalid 2FA code. {remaining} attempts remaining")

            if self.login_attempts < MAX_LOGIN_ATTEMPTS:
                self.ask_master_password()
            else:
                self.root.quit()

    def style_application(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("Custom.Treeview", background= "#ffffff", foreground="2d3436", rowheight= 35, font=("Satoshi", 10))
        style.map("Custom.Treeview", background=[('selected', '#3498bd')], foreground=[('selected', 'white')])
        style.configure("Custom.Treeview.Heading", background="dfe6e9", font=("Satoshi", 10, "bold"))

    def setup_gui(self):
        # title
        title_frame = tk.Frame(self.root, bg="#2c3e50", height=70)
        title_frame.pack(fill=tk.X)
        title_frame.pack_propagate(False)
        tk.Label(title_frame, text="Secure Password Manager", font=("Satoshi", 18,"bold"), bg="#2c3e50" , fg="#ecf0f1").pack(pady=10)


        #search bar 
        search_frame = tk.Frame(self.root, bg= "#f8f9fa", pady=15)
        search_frame.pack(fill=tk.X, padx=20)

        search_container = tk.Frame(search_frame, bg="#f8f9fa")
        search_container.pack(expand=True)

        tk.Label(search_container, text="Search:", font=("Satoshi", 10), bg= "#f8f9fa").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        search_entry = tk.Entry(search_container, textvariable= self.search_var, width=50, font=("Arial", 10))
        search_entry.pack(side=tk.LEFT, padx=5)
        search_entry.bind('<KeyRelease>', lambda e: self.load_passwords())

        # buttons
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=5)

        tk.Button(btn_frame, text="Add New", command=self.add_entry, bg="#4CAF50" , fg="white", width=15, font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Refresh", command=self.load_passwords, bg="#2196F3" , fg="white", width=15, font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Exit", command=self.root.quit, bg="#f44336" , fg="white", width=15, font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=5)

        # treeview
        tree_frame = tk.Frame(self.root)
        tree_frame.pack(padx=20 , pady=10 , fill=tk.BOTH, expand=True)

        scrollbar  =ttk.Scrollbar(tree_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)


        columns = ("website", "username", "password", "notes")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings", yscrollcommand=scrollbar.set)
        self.tree.pack(padx=2, pady=10, fill=tk.BOTH, expand=True)

        self.tree.heading("website", text= "Website/Service")
        self.tree.heading("username", text= "Username/Email")
        self.tree.heading("password", text= "password")
        self.tree.heading("notes", text= "Notes")

        self.tree.column("website", width=200)
        self.tree.column("username", width=200)
        self.tree.column("password", width=120, anchor=tk.CENTER)
        self.tree.column("notes", width=180)

        # right click menu 
        self.menu = tk.Menu(self.root, tearoff=0)
        self.menu.add_command(label = "Copy password", command= self.copy_password)
        self.menu.add_command(label = "Edit", command= self.edit_entry)
        self.menu.add_command(label = "Delete", command= self.delete_entry)
        self.tree.bind("<Button-3>", self.show_context_menu)

        # status bar
        self.status_bar = tk.Label(self.root, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W, font=("Arial", 9))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def encrypt(self, text: str)-> str:
        if self.fernet is None:
            raise ValueError("Master password not unlocked")
        return self.fernet.encrypt(text.encode()).decode()
    
    def decrypt(self, token: str)-> str:
        if self.fernet is None:
            raise ValueError("Master password not unlocked")
        
        try:
            token_bytes = token.encode()
            decrypted_bytes = self.fernet.decrypt(token_bytes)
            return decrypted_bytes.decode()
        except Exception as e :
            print(f"DEBUG: Cryptography Error: {type(e).__name__} - {e}")
            raise e 

    def load_passwords(self):
        if self.tree is None:
            return
        
        for items in self.tree.get_children():
            self.tree.delete(items)

        search_item = self.search_var.get().lower() if self.search_var else ""

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT id , website, username, password, notes FROM vault ORDER BY website")
        rows = c.fetchall()
        conn.close()

        count = 0
        for row in rows:
            id_, website, username, enc_pass, notes = row 
            try:
                password = self.decrypt(enc_pass)
            except:
                password = "Decryption Error"

            website_lower =website.lower()  if website else ""
            username_lower = username.lower() if username else ""
            notes_lower = notes.lower() if notes else ""

            if (search_item in website_lower or search_item in username_lower or search_item in notes_lower):
                self.tree.insert("", tk.END, values=(website, username or "","••••••••", notes or ""), tags=(id_,))

                count +=1

        if hasattr(self, 'status_bar') and self.status_bar:
            self.status_bar.config(text=f"Showing {count} entries")
        # conn.close()

    def add_entry(self):
        self.show_entry_dailog()

    def edit_entry(self):
        if self.tree is None:
            return
        selected = self.tree.selection()
        if not selected :
            messagebox.showwarning("No Selection","Please select an entry to edit") 
            return                
        item = self.tree.item(selected[0])
        entry_id = item['tags'][0]
        values = item['values']

        #fetch real password for editing
        conn = sqlite3.connect(DB_NAME)
        c= conn.cursor()
        c.execute("SELECT password  FROM vault WHERE  id=?", (entry_id,))
        result = c.fetchone()
        conn.close()

        if result:
            enc_pass = result[0]

            try:
                real_password = self.decrypt(enc_pass)
                self.show_entry_dailog(edit_mode=True, entry_id=entry_id, current=values, password =real_password)
            except:
                messagebox.showerror("Error", "Failed to decrypt password")


        # self.show_entry_dailog(edit_mode=True, entry_id = entry_id, current = values)

    def show_entry_dailog(self, edit_mode= False, entry_id=None, current = None , password=None):
        dailog = tk.Toplevel(self.root)
        dailog.title("Edit Entry" if edit_mode else "Add New Entry")
        dailog.geometry("500x450")
        dailog.transient(self.root)
        dailog.grab_set()

        tk.Label(dailog, text="Website/Service:" ,font=("Arial", 10, "bold")).pack(pady=5)
        website_entry = tk.Entry(dailog, width=50,font=("Arial", 10))
        website_entry.pack(pady=5)

        tk.Label(dailog, text="Username/Email:",font=("Arial", 10, "bold")).pack(pady=5)
        username_entry = tk.Entry(dailog, width=50,font=("Arial", 10))
        username_entry.pack(pady=5)

        tk.Label(dailog, text="Password:",font=("Arial", 10, "bold")).pack(pady=5)
        password_frame = tk.Entry(dailog, width=50,font=("Arial", 10))
        password_frame.pack(pady=5)

        show_password = tk.BooleanVar()
        password_entry = tk.Entry(password_frame, width=43,font=("Arial", 10), show="*")
        password_entry.pack(side=tk.LEFT)

        def toggle_password():
            if show_password.get():
                password_entry.config(show="")
            else:
                password_entry.config(show="*")

        tk.Checkbutton(password_frame, text="show", variable=show_password, command=toggle_password).pack(side=tk.LEFT, padx=5)

        tk.Label(dailog, text="Notes(optional):",font=("Arial", 10, "bold")).pack(pady=5)
        notes_entry = tk.Entry(dailog, width=50,font=("Arial", 10))
        notes_entry.pack(pady=5)

        # generate password button
        def generate_password():
            import secrets
            import string
            chars = string.ascii_letters + string.digits + "!@#$%^&*"
            new_pass = ''.join(secrets.choice(chars) for _ in range(20))
            password_entry.delete(0, tk.END)
            password_entry.insert(0, new_pass)

        tk.Button(dailog, text="Generate Strong Password (20 chars)",
                  command=generate_password , bg="#FF9800", fg="white" ,font=("Arial", 9, "bold")).pack(pady=10)
        
        if edit_mode and current:
            website_entry.insert(0, current[0])
            username_entry.insert(0, current[1] if current[1] != "" else "")
            notes_entry.insert(0, current[3] if current[3] else "")
            if password:
                password_entry.insert(0, password)
            
        def save():
            website = website_entry.get().strip()
            username =  username_entry.get().strip()
            password_text =  password_entry.get().strip()
            notes = notes_entry.get().strip() or None

            if not website or not password_text:
                messagebox.showerror("Error", "Website and Password are required")
                return
            
            enc_password =  self.encrypt(password_text)

            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()

            if edit_mode:
                c.execute('''UPDATE vault SET website=?, username=?, password=?, notes=?, modified_at=CURRENT_TIMESTAMP WHERE id=?''',
                          (website, username,enc_password, notes, entry_id))
            else:
                 c.execute('''INSERT INTO vault (website, username,password, notes) VALUES (?, ?, ?, ?)''',
                          (website, username, enc_password, notes))  
            conn.commit()
            conn.close()

            dailog.destroy()
            self.load_passwords()
            messagebox.showinfo("Success", "Password saved successfully")

        #save button 
        btn_frame = tk.Frame(dailog)
        btn_frame.pack(pady=15)
        tk.Button(btn_frame, text="Save", command= save, bg="#4CAF50",fg="white" , width=15, font=("Arial", 11, "bold")).pack(side=tk.LEFT,padx=10)
        tk.Button(btn_frame, text="cancel", command= dailog.destroy, bg="#f44336",fg="white", width=15, font=("Arial", 11, "bold")).pack(side=tk.LEFT,padx=5)

    def delete_entry(self):

        if self.tree is None:
            return
        
        selected = self.tree.selection()
        if not selected:
            return
        
        item = self.tree.item(selected[0])
        website = item['values'][0]

        if messagebox.askyesno("Delete entry", "Permanently delete this entry '{website}'?"):
            entry_id = item['tags'][0]
            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            c.execute("DELETE FROM vault WHERE id=?", (entry_id,))
            conn.commit()
            conn.close()
            self.load_passwords()
            messagebox.showinfo("Deleted", "Entry deleted successfully")

    def copy_password(self):
        if self.tree is None:
            return
        
        selected = self.tree.selection()
        if not selected:
            return
        
        raw_id = self.tree.item(selected[0])['tags'][0]
        str_id = str(raw_id)

        if not str_id.isdigit():
            messagebox.showerror("Error", "Invalid entry id")
            return
        
        entry_id = int(str_id)

        try :
            conn =sqlite3.connect(DB_NAME)
            c = conn.cursor()
            c.execute("SELECT password FROM vault WHERE id=?", (entry_id,))
            result = c.fetchone()
            conn.close()

            if  not result:
                return
            enc_pass = result[0]
        
            password =  self.decrypt(enc_pass)
            pyperclip.copy(password)

            password = "x"*len(password)
            del password

            if hasattr(self, 'status_bar') and self.status_bar:
                self.status_bar.config(text="Password copied to clipboard (will clear in 30s)")

            self.root.after(30000, lambda: pyperclip.copy(""))


        except:
            messagebox.showerror("Error", "Failed to decrypt password")

    def show_context_menu(self, event):
            if self.tree is None or self.menu is None:
                return
            try:
                item = self.tree.identify_row(event.y)
                if item:
                    self.tree.selection_set(item)
                    self.menu.tk_popup(event.x_root, event.y_root)
            finally:
                self.menu.grab_release()

    def copy_username(self):
        if self.tree is None:
            return
        
        selected = self.tree.selection()
        if not selected:
            return 
        username = self.tree.item(selected[0])['values'][1]

        if username:
            pyperclip.copy(username)
            if hasattr(self , 'status_bar') and self.status_bar:
                self.status_bar.config(text="Username copied to clipboard")
    
    def secure_exit(self):
        if messagebox.askyesno("Exit", "Are you sure you want to exit?"):
            if self.fernet:
                self.fernet = None
            if self.master_password:
                self.master_password = None

            try:
                pyperclip.copy("")
            except:
                pass
            self.root.quit()
            


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()
