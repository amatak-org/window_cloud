import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import sqlite3
import hashlib
import os
from flask import Flask, request, jsonify
import threading
from PIL import Image, ImageTk

app = Flask(__name__)

# Database setup
conn = sqlite3.connect('users.db', check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS users
                  (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, email TEXT)''')
cursor.execute('''CREATE TABLE IF NOT EXISTS uploads
                  (id INTEGER PRIMARY KEY, user_id INTEGER, filename TEXT, filepath TEXT, is_folder INTEGER)''')
conn.commit()

@app.route('/')
def home():
    return "Flask server is running!"

@app.route('/upload', methods=['POST'])
def upload():
    user_id = request.form.get('user_id')
    file = request.files['file']
    filename = file.filename
    filepath = os.path.join('uploads', filename)
    file.save(filepath)
    
    cursor.execute("INSERT INTO uploads (user_id, filename, filepath, is_folder) VALUES (?, ?, ?, ?)",
                   (user_id, filename, filepath, 0))
    conn.commit()
    
    return jsonify({"message": "File uploaded successfully"})

def run_flask():
    app.run(host='0.0.0.0', port=5000)

class UserApp:
    def __init__(self, master):
        self.master = master
        self.master.title("User Application")
        self.master.geometry("1000x600")
        
        self.current_user = None
        
        self.notebook = ttk.Notebook(self.master)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        self.login_frame = ttk.Frame(self.notebook, padding="10")
        self.signup_frame = ttk.Frame(self.notebook, padding="10")
        self.dashboard_frame = ttk.Frame(self.notebook, padding="10")
        self.profile_frame = ttk.Frame(self.notebook, padding="10")
        self.settings_frame = ttk.Frame(self.notebook, padding="10")
        self.gallery_frame = ttk.Frame(self.notebook, padding="10")
        self.file_view_frame = ttk.Frame(self.notebook, padding="10")
        
        self.notebook.add(self.login_frame, text="Login")
        self.notebook.add(self.signup_frame, text="Sign Up")
        
        self.setup_login_frame()
        self.setup_signup_frame()
        self.setup_dashboard_frame()
        self.setup_profile_frame()
        self.setup_settings_frame()
        self.setup_gallery_frame()
        self.setup_file_view_frame()
    
    def setup_login_frame(self):
        ttk.Label(self.login_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.login_username = ttk.Entry(self.login_frame)
        self.login_username.grid(row=0, column=1, pady=5)
        
        ttk.Label(self.login_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.login_password = ttk.Entry(self.login_frame, show="*")
        self.login_password.grid(row=1, column=1, pady=5)
        
        ttk.Button(self.login_frame, text="Login", command=self.login).grid(row=2, column=1, pady=10)
    
    def setup_signup_frame(self):
        ttk.Label(self.signup_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.signup_username = ttk.Entry(self.signup_frame)
        self.signup_username.grid(row=0, column=1, pady=5)
        
        ttk.Label(self.signup_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.signup_password = ttk.Entry(self.signup_frame, show="*")
        self.signup_password.grid(row=1, column=1, pady=5)
        
        ttk.Label(self.signup_frame, text="Email:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.signup_email = ttk.Entry(self.signup_frame)
        self.signup_email.grid(row=2, column=1, pady=5)
        
        ttk.Button(self.signup_frame, text="Sign Up", command=self.signup).grid(row=3, column=1, pady=10)
    
    def setup_dashboard_frame(self):
        self.tree = ttk.Treeview(self.dashboard_frame, columns=('ID', 'Filename', 'Filepath', 'Type'), show='headings')
        self.tree.heading('ID', text='ID')
        self.tree.heading('Filename', text='Filename')
        self.tree.heading('Filepath', text='Filepath')
        self.tree.heading('Type', text='Type')
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        button_frame = ttk.Frame(self.dashboard_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(button_frame, text="Upload File", command=self.upload_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Create Folder", command=self.create_folder).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="View Gallery", command=self.view_gallery).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Logout", command=self.logout).pack(side=tk.RIGHT, padx=5)
    
    def setup_profile_frame(self):
        self.profile_username_label = ttk.Label(self.profile_frame, text="Username: ")
        self.profile_username_label.pack(pady=5)
        
        self.profile_email_label = ttk.Label(self.profile_frame, text="Email: ")
        self.profile_email_label.pack(pady=5)
    
    def setup_settings_frame(self):
        ttk.Label(self.settings_frame, text="New Password:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.new_password = ttk.Entry(self.settings_frame, show="*")
        self.new_password.grid(row=0, column=1, pady=5)
        
        ttk.Label(self.settings_frame, text="Confirm Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.confirm_password = ttk.Entry(self.settings_frame, show="*")
        self.confirm_password.grid(row=1, column=1, pady=5)
        
        ttk.Button(self.settings_frame, text="Change Password", command=self.change_password).grid(row=2, column=1, pady=10)
    
    def setup_gallery_frame(self):
        self.gallery_canvas = tk.Canvas(self.gallery_frame)
        self.gallery_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(self.gallery_frame, orient=tk.VERTICAL, command=self.gallery_canvas.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.gallery_canvas.configure(yscrollcommand=scrollbar.set)
        self.gallery_canvas.bind('<Configure>', lambda e: self.gallery_canvas.configure(scrollregion=self.gallery_canvas.bbox("all")))
        
        self.gallery_inner_frame = ttk.Frame(self.gallery_canvas)
        self.gallery_canvas.create_window((0, 0), window=self.gallery_inner_frame, anchor="nw")
    
    def setup_file_view_frame(self):
        self.file_view_label = ttk.Label(self.file_view_frame, text="")
        self.file_view_label.pack(pady=10)
        
        self.file_content = tk.Text(self.file_view_frame, wrap=tk.WORD, height=20, width=80)
        self.file_content.pack(pady=10)
        
        self.file_image = ttk.Label(self.file_view_frame)
        self.file_image.pack(pady=10)
    
    def login(self):
        username = self.login_username.get()
        password = self.login_password.get()
        
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hashed_password))
        user = cursor.fetchone()
        
        if user:
            self.current_user = user
            self.load_user_data()
            self.notebook.forget(0)
            self.notebook.forget(0)
            self.notebook.add(self.dashboard_frame, text="Dashboard")
            self.notebook.add(self.profile_frame, text="Profile")
            self.notebook.add(self.settings_frame, text="Settings")
            self.notebook.add(self.gallery_frame, text="Gallery")
            self.notebook.select(self.dashboard_frame)
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")
    
    def signup(self):
        username = self.signup_username.get()
        password = self.signup_password.get()
        email = self.signup_email.get()
        
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        try:
            cursor.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                           (username, hashed_password, email))
            conn.commit()
            messagebox.showinfo("Success", "Account created successfully")
            self.notebook.select(self.login_frame)
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Username already exists")
    
    def logout(self):
        self.current_user = None
        for i in range(self.notebook.index("end")-1, -1, -1):
            self.notebook.forget(i)
        self.notebook.add(self.login_frame, text="Login")
        self.notebook.add(self.signup_frame, text="Sign Up")
        self.notebook.select(self.login_frame)
    
    def load_user_data(self):
        self.tree.delete(*self.tree.get_children())
        cursor.execute("SELECT * FROM uploads WHERE user_id=?", (self.current_user[0],))
        for row in cursor.fetchall():
            self.tree.insert('', 'end', values=(row[0], row[2], row[3], "Folder" if row[4] else "File"))
        
        self.profile_username_label.config(text=f"Username: {self.current_user[1]}")
        self.profile_email_label.config(text=f"Email: {self.current_user[3]}")
        
        self.load_gallery()
    
    def upload_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            filename = os.path.basename(file_path)
            cursor.execute("INSERT INTO uploads (user_id, filename, filepath, is_folder) VALUES (?, ?, ?, ?)",
                           (self.current_user[0], filename, file_path, 0))
            conn.commit()
            self.load_user_data()
            messagebox.showinfo("Success", "File uploaded successfully")
    
    def create_folder(self):
        folder_name = filedialog.askstring("Create Folder", "Enter folder name:")
        if folder_name:
            cursor.execute("INSERT INTO uploads (user_id, filename, filepath, is_folder) VALUES (?, ?, ?, ?)",
                           (self.current_user[0], folder_name, "", 1))
            conn.commit()
            self.load_user_data()
            messagebox.showinfo("Success", "Folder created successfully")
    
    def change_password(self):
        new_password = self.new_password.get()
        confirm_password = self.confirm_password.get()
        
        if new_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
        
        cursor.execute("UPDATE users SET password=? WHERE id=?", (hashed_password, self.current_user[0]))
        conn.commit()
        messagebox.showinfo("Success", "Password changed successfully")
        
        self.new_password.delete(0, tk.END)
        self.confirm_password.delete(0, tk.END)
    
    def view_gallery(self):
        self.notebook.select(self.gallery_frame)
    
    def load_gallery(self):
        for widget in self.gallery_inner_frame.winfo_children():
            widget.destroy()
        
        cursor.execute("SELECT * FROM uploads WHERE user_id=? AND is_folder=0", (self.current_user[0],))
        files = cursor.fetchall()
        
        row = 0
        col = 0
        for file in files:
            if file[3].lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
                img = Image.open(file[3])
                img.thumbnail((100, 100))
                photo = ImageTk.PhotoImage(img)
                
                label = ttk.Label(self.gallery_inner_frame, image=photo, text=file[2], compound=tk.TOP)
                label.image = photo
                label.grid(row=row, column=col, padx=5, pady=5)
                
                label.bind("<Button-1>", lambda e, f=file: self.view_file(f))
                
                col += 1
                if col > 4:
                    col = 0
                    row += 1
    
    def view_file(self, file):
        self.notebook.select(self.file_view_frame)
        self.file_view_label.config(text=f"File: {file[2]}")
        
        if file[3].lower().endswith(('.txt', '.py', '.html', '.css', '.js')):
            with open(file[3], 'r') as f:
                content = f.read()
            self.file_content.delete('1.0', tk.END)
            self.file_content.insert(tk.END, content)
            self.file_content.pack(pady=10)
            self.file_image.pack_forget()
        elif file[3].lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
            img = Image.open(file[3])
            img.thumbnail((400, 400))
            photo = ImageTk.PhotoImage(img)
            self.file_image.config(image=photo)
            self.file_image.image = photo
            self.file_content.pack_forget()
            self.file_image.pack(pady=10)
        else:
            self.file_content.delete('1.0', tk.END)
            self.file_content.insert(tk.END, "File type not supported for preview.")
            self.file_content.pack(pady=10)
            self.file_image.pack_forget()

def start_flask_server():
    threading.Thread(target=run_flask, daemon=True).start()
    messagebox.showinfo("Success", "Flask server started on port 5000")

root = tk.Tk()
user_app = UserApp(root)

menu_frame = ttk.Frame(root, padding="10")
menu_frame.pack(side=tk.BOTTOM, fill=tk.X)

ttk.Button(menu_frame, text="Start Flask Server", command=start_flask_server).pack(side=tk.LEFT, padx=5)

root.mainloop()
