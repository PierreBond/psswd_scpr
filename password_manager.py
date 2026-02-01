import tkinter as tk 
from tkinter import ttk, messagebox, simpledialog
import customtkinter as ctk
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

# Set appearance and theme
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

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
        self.root.geometry("1100x700")  # Adjusted size for better default look
        self.root.resizable(True, True)
        self.is_loading = False

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
        # We'll use a custom CTkToplevel for the setup process
        setup_window = ctk.CTkToplevel(self.root)
        setup_window.title("Initial Setup")
        setup_window.geometry("500x600")
        setup_window.attributes('-topmost', True)
        setup_window.grab_set()

        ctk.CTkLabel(setup_window, text="Create Master Password", font=("Satoshi", 24, "bold")).pack(pady=30)
        
        ctk.CTkLabel(setup_window, text="Requirements:\n• 12+ characters\n• Uppercase & lowercase\n• Number & symbol", 
                 font=("Satoshi", 12), justify=tk.LEFT).pack(pady=10)

        pw1 = ctk.CTkEntry(setup_window, width=350, placeholder_text="New Master Password", show="*")
        pw1.pack(pady=10)
        
        pw2 = ctk.CTkEntry(setup_window, width=350, placeholder_text="Confirm Password", show="*")
        pw2.pack(pady=10)

        def proceed_setup():
            master = pw1.get()
            confirm = pw2.get()
            
            if master != confirm:
                messagebox.showerror("Error", "Passwords do not match")
                return

            is_valid, message = validate_password_strength(master)
            if not is_valid:
                messagebox.showerror("Weak Password", message)
                return

            # Proceed to 2FA Setup
            setup_window.destroy()
            self._setup_2fa(master)

        ctk.CTkButton(setup_window, text="Create Vault", command=proceed_setup, 
                  fg_color="#27ae60", hover_color="#219150", width=350, height=45).pack(pady=30)

    def _setup_2fa(self, master):
        # Generate TOTP secret
        totp_secret = pyotp.random_base32()
        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
            name="LocalPasswordManager",
            issuer_name="MyPasswordManager"
        )

        # Create QR code 
        qr = pyqrcode.create(totp_uri)
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
            qr.png(tmp.name, scale=6)
            qr_path = tmp.name

        qr_window = ctk.CTkToplevel(self.root)
        qr_window.title("2FA Setup")
        qr_window.geometry("600x750")
        qr_window.grab_set()

        img = PhotoImage(file=qr_path)
        label = tk.Label(qr_window, image=img, bg="#2b2b2b") 
        setattr(label, "imge", img)
        label.pack(pady=20)

        ctk.CTkLabel(qr_window, text="Scan with Authenticator App", font=("Satoshi", 18, "bold")).pack(pady=10)
        
        ctk.CTkLabel(qr_window, text=f"Or enter manually: {totp_secret}", 
                 font=("Courier", 12), fg_color="#3d3d3d", corner_radius=5, padx=10, pady=5).pack(pady=10)

        code_entry = ctk.CTkEntry(qr_window, width=200, placeholder_text="Enter 6-digit code", font=("Satoshi", 16))
        code_entry.pack(pady=20)

        def verify_and_save():
            code = code_entry.get()
            if code and pyotp.TOTP(totp_secret).verify(code, valid_window=1):
                try: os.unlink(qr_path)
                except: pass
                qr_window.destroy()
                
                # encryption logic
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

                messagebox.showinfo("Success", "Vault setup successful!")
                self.setup_gui()
                self.load_passwords()
            else:
                messagebox.showerror("Error", "Invalid code")

        ctk.CTkButton(qr_window, text="Verify & Finish", command=verify_and_save, 
                  fg_color="#3498db", hover_color="#2980b9", width=200, height=45).pack(pady=10)


        def cleanup_and_quit(self, window, qr_path):
            try:
                os.unlink(qr_path)
            except:
                pass
            window.destroy()
            self.root.quit()


    def ask_master_password(self):
        login_window = ctk.CTkToplevel(self.root)
        login_window.title("Authentication Required")
        login_window.geometry("450x500")
        login_window.attributes('-topmost', True)
        login_window.grab_set()

        ctk.CTkLabel(login_window, text="Secure Vault", font=("Satoshi", 28, "bold")).pack(pady=40)
        
        pw_entry = ctk.CTkEntry(login_window, width=300, placeholder_text="Enter Master Password", show="*")
        pw_entry.pack(pady=10)
        
        code_entry = ctk.CTkEntry(login_window, width=300, placeholder_text="Enter 2FA Code")
        code_entry.pack(pady=10)

        def attempt_login():
            master = pw_entry.get()
            code = code_entry.get()
            
            if self.login_attempts >= MAX_LOGIN_ATTEMPTS:
                time_since_last = time.time() - self.last_failed_attempt
                if time_since_last < LOCKOUT_TIME:
                    remaining = int(LOCKOUT_TIME - time_since_last)
                    messagebox.showerror("Locked Out", f"Retry in {remaining}s")
                    return
                else:
                    self.login_attempts = 0

            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            c.execute("SELECT salt, totp_secret FROM master")
            row = c.fetchone()
            conn.close()

            if not row:
                messagebox.showerror("Error", "Database error")
                self.root.quit()
                return

            salt, encrypted_totp = row
            key = derive_key(master, salt)

            try:
                temp_fernet = Fernet(key)
                totp_secret = temp_fernet.decrypt(encrypted_totp.encode()).decode()
            except Exception:
                self.login_attempts += 1
                self.last_failed_attempt = time.time()
                messagebox.showerror("Login Failed", f"Invalid password. {MAX_LOGIN_ATTEMPTS - self.login_attempts} attempts left")
                return

            if code and pyotp.TOTP(totp_secret).verify(code):
                self.fernet = temp_fernet
                self.master_password = master
                self.login_attempts = 0
                login_window.destroy()
                self.setup_gui()
                self.load_passwords()
            else:
                self.login_attempts += 1
                self.last_failed_attempt = time.time()
                messagebox.showerror("Login Failed", "Invalid 2FA code")

        ctk.CTkButton(login_window, text="Unlock Vault", command=attempt_login, 
                  fg_color="#3498db", hover_color="#2980b9", width=300, height=45).pack(pady=30)
        
        login_window.protocol("WM_DELETE_WINDOW", self.root.quit)

    def style_application(self):
        style = ttk.Style()
        style.theme_use("clam")

        # Treeview coloring for dark mode
        style.configure("Custom.Treeview", 
                        background="#2b2b2b", 
                        foreground="white", 
                        fieldbackground="#2b2b2b", 
                        rowheight=35, 
                        font=("Satoshi", 11), 
                        borderwidth=0)
        
        style.map("Custom.Treeview", 
                  background=[('selected', '#3498db')], 
                  foreground=[('selected', 'white')])

        style.configure("Custom.Treeview.Heading", 
                        background="#3d3d3d", 
                        foreground="white", 
                        font=("Satoshi", 11, "bold"), 
                        relief="flat")
        
        style.map("Custom.Treeview.Heading", 
                  background=[('active', '#4d4d4d')])

    def setup_gui(self):
        self.style_application()
        
        # In CustomTkinter, we often use CTkFrame for better background handling
        self.main_container = ctk.CTkFrame(self.root)
        self.main_container.pack(fill=tk.BOTH, expand=True)

        self.sidebar = ctk.CTkFrame(self.main_container, width=220, corner_radius=0)
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y)
        self.sidebar.pack_propagate(False) 
        
        self.setup_sidebar_content()

        self.content_area = ctk.CTkFrame(self.main_container, corner_radius=0)
        self.content_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.setup_dashboard_header()
        self.setup_main_table()
        
        self.load_passwords()

        self.status_bar = ctk.CTkLabel(self.root, text="Ready", 
                           anchor=tk.W, 
                           font=("Satoshi", 12), padx=20)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, pady=(0, 5))

    def setup_sidebar_content(self):
        ctk.CTkLabel(self.sidebar, text="AVA", font=("Satoshi", 32, "bold"), 
                 text_color="#3498db").pack(pady=(40, 5))
        
        ctk.CTkLabel(self.sidebar, text="Secure Vault", font=("Satoshi", 14, "bold"), 
                 text_color="#ecf0f1").pack(pady=(0, 40))

        menu_items = [
            ("Dashboard", self.load_main_dashboard),
            ("Security Audit", self.run_security_audit),
            ("Settings", self.show_settings)  
        ]

        for text, cmd in menu_items:
            btn = ctk.CTkButton(self.sidebar, text=text, font=("Satoshi", 13),
                            fg_color="transparent", text_color="#bdc3c7", 
                            hover_color="#34495e",
                            anchor="w", corner_radius=0, height=45,
                            command=cmd)
            btn.pack(fill=tk.X, padx=10, pady=2)

        ctk.CTkLabel(self.sidebar, text="v1.0.0 • Encrypted", font=("Satoshi", 10),
                 text_color="#7f8c8d").pack(side=tk.BOTTOM, pady=20)
        

    def load_main_dashboard(self):
        self.clear_content_area()
        self.setup_dashboard_header()
        self.setup_main_table()
        self.root.after(10, self.load_passwords)
    def setup_dashboard_header(self):      
        top_bar = ctk.CTkFrame(self.content_area, fg_color="transparent")
        top_bar.pack(fill=tk.X, padx=30, pady=(30, 20))

        ctk.CTkLabel(top_bar, text="All Passwords", font=("Satoshi", 28, "bold")).pack(side=tk.LEFT)

        ctk.CTkButton(top_bar, text=" New Entry", command=self.add_entry, 
                  fg_color="#27ae60", hover_color="#219150", font=("Satoshi", 13, "bold"), 
                  width=120, height=40).pack(side=tk.RIGHT)

        search_container = ctk.CTkFrame(self.content_area, fg_color="#2b2b2b", corner_radius=10)
        search_container.pack(fill=tk.X, padx=30, pady=(0, 20))
        
        ctk.CTkLabel(search_container, text="search", font=("Satoshi", 16)).pack(side=tk.LEFT, padx=10)

        self.search_var = tk.StringVar()
        self.search_entry = ctk.CTkEntry(search_container, textvariable=self.search_var, 
                                     font=("Satoshi", 13), border_width=0, fg_color="transparent",
                                     placeholder_text="Search accounts...")
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, pady=5)
        self.search_entry.bind('<KeyRelease>', lambda e: self.load_passwords())

        ctk.CTkButton(search_container, text="✕", command=self.clear_search, 
                  fg_color="transparent", hover_color="#3d3d3d", width=30, height=30).pack(side=tk.RIGHT, padx=5)

    def setup_main_table(self):
        # Container for the table to give it a white card-like background
        table_card = ctk.CTkFrame(self.content_area, fg_color="#1e1e1e", corner_radius=15)
        table_card.pack(fill=tk.BOTH, expand=True, padx=30, pady=(0, 30))

        scrollbar = ttk.Scrollbar(table_card)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        columns = ("website", "username", "password", "notes")
        self.tree = ttk.Treeview(table_card, columns=columns, show="headings", 
                                 yscrollcommand=scrollbar.set, style="Custom.Treeview")
        self.tree.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.tree.yview)

        # Column Configuration
        self.tree.heading("website", text="WEBSITE")
        self.tree.heading("username", text="USERNAME")
        self.tree.heading("password", text="PASSWORD")
        self.tree.heading("notes", text="NOTES")

        self.tree.column("website", width=180)
        self.tree.column("username", width=220)
        self.tree.column("password", width=120, anchor="center")
        self.tree.column("notes", width=200)

        # right click menu 
        self.menu = tk.Menu(self.root, tearoff=0,bg = "white", font=("Satoshi", 10))
        self.menu.add_command(label = "Copy password", command= self.copy_password)
        self.menu.add_command(label = "Copy username", command= self.copy_username)
        self.menu.add_separator()
        self.menu.add_command(label = "Edit", command= self.edit_entry)
        self.menu.add_command(label = "Delete", command= self.delete_entry)
        self.tree.bind("<Button-3>", self.show_context_menu)



    def run_security_audit(self):
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT website, password FROM vault")
        rows = c.fetchall()
        conn.close()

        if not rows:
            messagebox.showinfo("Security Audit", "Vault is empty. Nothing to audit!")
            return

        # Dictionary to track which encrypted passwords are used where
        password_map = {}
        duplicates = []

        for website, enc_pass in rows:
            if enc_pass in password_map:
                duplicates.append(f"• {website} (same as {password_map[enc_pass]})")
            else:
                password_map[enc_pass] = website

        if duplicates:
            report = " Reused Passwords Found:\n\n" + "\n".join(duplicates)
            report += "\n\nIt is recommended to use unique passwords for every site."
            messagebox.showwarning("Security Audit Result", report)
        else:
            messagebox.showinfo("Security Audit Result", "No reused passwords found! Your vault looks secure.")
    def clear_search(self):
        if self.search_var is not None:
            self.search_var.set("")
            
        self.load_passwords()
        
        if self.search_entry is not None:
            self.search_entry.focus()


    def clear_content_area(self):
        if  hasattr(self, 'tree') and self.tree:
            self.tree.unbind("<Button-3>")
       
        for widget in self.content_area.winfo_children():
            widget.destroy()    

        self.tree = None    

    def show_settings(self):
        self.clear_content_area()
        
        container = ctk.CTkFrame(self.content_area, corner_radius=15)
        container.pack(fill=tk.BOTH, expand=True, padx=30, pady=30)

        ctk.CTkLabel(container, text="Settings", font=("Satoshi", 24, "bold")).pack(anchor="w", padx=40, pady=(40, 20))

        ctk.CTkLabel(container, text="SECURITY", font=("Satoshi", 11, "bold"), 
                 text_color="#7f8c8d").pack(anchor="w", padx=40, pady=(10, 5))

        clip_frame = ctk.CTkFrame(container, fg_color="transparent")
        clip_frame.pack(fill=tk.X, padx=40, pady=10)
        
        ctk.CTkLabel(clip_frame, text="Clear clipboard after (seconds):", 
                 font=("Satoshi", 13)).pack(side=tk.LEFT)
        
        self.clip_delay = tk.Spinbox(clip_frame, from_=5, to=300, width=5)
        self.clip_delay.pack(side=tk.RIGHT)

        ctk.CTkLabel(container, text="DATABASE", font=("Satoshi", 11, "bold"), 
                 text_color="#7f8c8d").pack(anchor="w", padx=40, pady=(20, 5))

        ctk.CTkButton(container, text="Export Vault (JSON)", fg_color="#3d3d3d", hover_color="#4d4d4d",
                 font=("Satoshi", 12), width=200).pack(anchor="w", padx=40, pady=5)
        
        ctk.CTkButton(container, text="Change Master Password", fg_color="#3d3d3d", hover_color="#4d4d4d",
                 font=("Satoshi", 12), width=200).pack(anchor="w", padx=40, pady=5)

        ctk.CTkButton(container, text="Wipe All Data", fg_color="#e74c3c", hover_color="#c0392b", 
                 font=("Satoshi", 12, "bold"), width=200).pack(side=tk.BOTTOM, anchor="w", padx=40, pady=40)

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

    def load_passwords(self, event=None):
        print("Debug: load_passwords called")

        if getattr(self, 'is_loading', False):
            print("Debug: Glocked by lock")
            return 
        
        if not hasattr(self, 'tree' ) or self.tree is None:
            return

        self.is_loading = True 
        try:
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
                # try:
                #     password = self.decrypt(enc_pass)
                # except:
                #     password = "Decryption Error"

                website_lower =website.lower()  if website else ""
                username_lower = username.lower() if username else ""
                notes_lower = notes.lower() if notes else ""

                if not search_item or (search_item in website_lower or search_item in username_lower or search_item in notes_lower):
                    self.tree.insert("", tk.END, values=(website, username or "","••••••••", notes or ""), tags=(id_,))

                    count +=1

            if hasattr(self, 'status_bar') and self.status_bar:
                self.status_bar.config(text=f"Showing {count} entries")
            # conn.close()

        finally:
            self.is_loading = False 

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
        dailog = ctk.CTkToplevel(self.root)
        dailog.title("Edit Entry" if edit_mode else "Add New Entry")
        dailog.geometry("500x550")
        dailog.transient(self.root)
        dailog.grab_set()

        ctk.CTkLabel(dailog, text="Website/Service:", font=("Satoshi", 13, "bold")).pack(pady=(20, 5), padx=20, anchor="w")
        website_entry = ctk.CTkEntry(dailog, width=460, font=("Satoshi", 13), placeholder_text="e.g. google.com")
        website_entry.pack(pady=5, padx=20)

        ctk.CTkLabel(dailog, text="Username/Email:", font=("Satoshi", 13, "bold")).pack(pady=(10, 5), padx=20, anchor="w")
        username_entry = ctk.CTkEntry(dailog, width=460, font=("Satoshi", 13), placeholder_text="e.g. user@example.com")
        username_entry.pack(pady=5, padx=20)

        ctk.CTkLabel(dailog, text="Password:", font=("Satoshi", 13, "bold")).pack(pady=(10, 5), padx=20, anchor="w")
        
        password_frame = ctk.CTkFrame(dailog, fg_color="transparent")
        password_frame.pack(fill=tk.X, padx=20, pady=5)

        show_password = tk.BooleanVar()
        password_entry = ctk.CTkEntry(password_frame, width=380, font=("Satoshi", 13), show="*")
        password_entry.pack(side=tk.LEFT)

        def toggle_password():
            if show_password.get():
                password_entry.config(show="")
            else:
                password_entry.config(show="*")

        ctk.CTkCheckBox(password_frame, text="Show", variable=show_password, command=toggle_password, width=60).pack(side=tk.LEFT, padx=5)

        ctk.CTkLabel(dailog, text="Notes (optional):", font=("Satoshi", 13, "bold")).pack(pady=(10, 5), padx=20, anchor="w")
        notes_entry = ctk.CTkEntry(dailog, width=460, font=("Satoshi", 13), placeholder_text="Add any additional details...")
        notes_entry.pack(pady=5, padx=20)

        # generate password button
        def generate_password():
            import secrets
            import string
            chars = string.ascii_letters + string.digits + "!@#$%^&*"
            new_pass = ''.join(secrets.choice(chars) for _ in range(20))
            password_entry.delete(0, tk.END)
            password_entry.insert(0, new_pass)

        ctk.CTkButton(dailog, text="Generate Strong Password",
                  command=generate_password, fg_color="#e67e22", hover_color="#d35400", 
                  font=("Satoshi", 12, "bold"), height=35).pack(pady=15)
        
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
        btn_frame = ctk.CTkFrame(dailog, fg_color="transparent")
        btn_frame.pack(pady=20, padx=20, fill=tk.X)
        
        ctk.CTkButton(btn_frame, text="Save Entry", command=save, fg_color="#2ecc71", hover_color="#27ae60", 
                  width=210, height=45, font=("Satoshi", 14, "bold")).pack(side=tk.LEFT, expand=True, padx=(0, 5))
        
        ctk.CTkButton(btn_frame, text="Cancel", command=dailog.destroy, fg_color="#95a5a6", hover_color="#7f8c8d", 
                  width=210, height=45, font=("Satoshi", 14, "bold")).pack(side=tk.LEFT, expand=True, padx=(5, 0))

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
                    self.tree.focus(item)
                    self.menu.post(event.x_root, event.y_root)
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
    import ctypes 

    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except  Exception:
        ctypes.windll.user32.SetProcessDPIAware()


    root = ctk.CTk()
    app = PasswordManager(root)
    root.mainloop()
