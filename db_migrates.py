import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import sqlite3
import hashlib
import os
import threading
import subprocess
from flask import Flask
import pygments
from pygments.lexers import get_lexer_by_name
from pygments.formatters import get_formatter_by_name
import pty
import select
import termios
import struct
import fcntl
import alembic
from alembic.config import Config
from alembic import command
from sqlalchemy import create_engine, Column, Integer, String, MetaData
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

app = Flask(__name__)

# Database setup
engine = create_engine('sqlite:///users.db')
Base = declarative_base()
Session = sessionmaker(bind=engine)
session = Session()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password = Column(String)
    email = Column(String)

class InstalledApp(Base):
    __tablename__ = 'installed_apps'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
    app_name = Column(String)

Base.metadata.create_all(engine)

# Alembic setup
alembic_cfg = Config("alembic.ini")
command.init(alembic_cfg, "alembic")

@app.route('/')
def home():
    return "Flask server is running!"

def run_flask():
    app.run(host='0.0.0.0', port=5000)

class Terminal(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.terminal = scrolledtext.ScrolledText(self, wrap=tk.WORD, width=80, height=24, bg="black", fg="white")
        self.terminal.pack(expand=True, fill='both')
        self.terminal.bind("<Key>", self.key_press)

        self.master, self.slave = pty.openpty()
        self.process = subprocess.Popen(
            ["/bin/bash"],
            stdin=self.slave,
            stdout=self.slave,
            stderr=self.slave,
            universal_newlines=True
        )
        
        self.terminal.after(10, self.read_output)

    def key_press(self, event):
        if event.char:
            os.write(self.master, event.char.encode())
        return "break"

    def read_output(self):
        max_read_bytes = 1024 * 10
        ready, _, _ = select.select([self.master], [], [], 0.1)
        if ready:
            output = os.read(self.master, max_read_bytes).decode()
            self.terminal.insert(tk.END, output)
            self.terminal.see(tk.END)
        self.terminal.after(10, self.read_output)

class CodeEditor(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.text_widget = scrolledtext.ScrolledText(self, wrap=tk.WORD, width=80, height=20)
        self.text_widget.pack(expand=True, fill='both')
        
        self.language_var = tk.StringVar(value="python")
        languages = ["python", "javascript", "html", "css"]
        language_menu = ttk.OptionMenu(self, self.language_var, "python", *languages, command=self.highlight_syntax)
        language_menu.pack()

        button_frame = ttk.Frame(self)
        button_frame.pack(fill='x')
        ttk.Button(button_frame, text="Open", command=self.open_file).pack(side='left')
        ttk.Button(button_frame, text="Save", command=self.save_file).pack(side='left')
        ttk.Button(button_frame, text="Run", command=self.run_code).pack(side='left')

        self.output = scrolledtext.ScrolledText(self, wrap=tk.WORD, width=80, height=10)
        self.output.pack(expand=True, fill='both')

    def highlight_syntax(self, *args):
        code = self.text_widget.get("1.0", tk.END)
        lexer = get_lexer_by_name(self.language_var.get(), stripall=True)
        formatter = get_formatter_by_name("html", style="colorful", noclasses=True)
        highlighted = pygments.highlight(code, lexer, formatter)
        
        self.text_widget.delete("1.0", tk.END)
        self.text_widget.insert(tk.END, highlighted)

    def open_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            with open(file_path, 'r') as file:
                content = file.read()
                self.text_widget.delete("1.0", tk.END)
                self.text_widget.insert(tk.END, content)
            self.highlight_syntax()

    def save_file(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".py")
        if file_path:
            content = self.text_widget.get("1.0", tk.END)
            with open(file_path, 'w') as file:
                file.write(content)
            messagebox.showinfo("Save", "File saved successfully")

    def run_code(self):
        code = self.text_widget.get("1.0", tk.END)
        try:
            result = subprocess.run(["python", "-c", code], capture_output=True, text=True, timeout=5)
            self.output.delete("1.0", tk.END)
            self.output.insert(tk.END, result.stdout)
            if result.stderr:
                self.output.insert(tk.END, "\nErrors:\n" + result.stderr)
        except subprocess.TimeoutExpired:
            self.output.delete("1.0", tk.END)
            self.output.insert(tk.END, "Execution timed out")
        except Exception as e:
            self.output.delete("1.0", tk.END)
            self.output.insert(tk.END, f"An error occurred: {str(e)}")

class UserApp:
    def __init__(self, master):
        self.master = master
        self.master.title("User Application")
        self.master.geometry("1200x800")
        
        self.current_user = None
        
        self.notebook = ttk.Notebook(self.master)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        self.login_frame = ttk.Frame(self.notebook, padding="10")
        self.signup_frame = ttk.Frame(self.notebook, padding="10")
        self.dashboard_frame = ttk.Frame(self.notebook, padding="10")
        self.profile_frame = ttk.Frame(self.notebook, padding="10")
        self.settings_frame = ttk.Frame(self.notebook, padding="10")
        self.app_store_frame = ttk.Frame(self.notebook, padding="10")
        self.installed_apps_frame = ttk.Frame(self.notebook, padding="10")
        self.code_editor_frame = ttk.Frame(self.notebook, padding="10")
        self.terminal_frame = ttk.Frame(self.notebook, padding="10")
        self.db_migration_frame = ttk.Frame(self.notebook, padding="10")
        
        self.notebook.add(self.login_frame, text="Login")
        self.notebook.add(self.signup_frame, text="Sign Up")
        
        self.setup_login_frame()
        self.setup_signup_frame()
        self.setup_dashboard_frame()
        self.setup_profile_frame()
        self.setup_settings_frame()
        self.setup_app_store_frame()
        self.setup_installed_apps_frame()
        self.setup_code_editor_frame()
        self.setup_terminal_frame()
        self.setup_db_migration_frame()
    
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
        ttk.Label(self.dashboard_frame, text="Welcome to the Dashboard!").pack(pady=20)
        ttk.Button(self.dashboard_frame, text="Logout", command=self.logout).pack(pady=10)
    
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
    
    def setup_app_store_frame(self):
        self.available_apps = ["nginx", "php", "nodejs", "python", "mysql"]
        
        for app in self.available_apps:
            ttk.Button(self.app_store_frame, text=f"Install {app}", command=lambda a=app: self.install_app(a)).pack(pady=5)
        
        self.install_progress = scrolledtext.ScrolledText(self.app_store_frame, height=10, width=50)
        self.install_progress.pack(pady=10)
    
    def setup_installed_apps_frame(self):
        self.installed_apps_list = ttk.Treeview(self.installed_apps_frame, columns=('App Name',), show='headings')
        self.installed_apps_list.heading('App Name', text='App Name')
        self.installed_apps_list.pack(fill=tk.BOTH, expand=True)
    
    def setup_code_editor_frame(self):
        self.code_editor = CodeEditor(self.code_editor_frame)
        self.code_editor.pack(fill=tk.BOTH, expand=True)
    
    def setup_terminal_frame(self):
        self.terminal = Terminal(self.terminal_frame)
        self.terminal.pack(fill=tk.BOTH, expand=True)
    
    def setup_db_migration_frame(self):
        ttk.Button(self.db_migration_frame, text="Create New Table", command=self.create_new_table).pack(pady=10)
        ttk.Button(self.db_migration_frame, text="Make Migrations", command=self.make_migrations).pack(pady=10)
        ttk.Button(self.db_migration_frame, text="Apply Migrations", command=self.apply_migrations).pack(pady=10)
        
        self.migration_output = scrolledtext.ScrolledText(self.db_migration_frame, height=10, width=50)
        self.migration_output.pack(pady=10)
    
    def login(self):
        username = self.login_username.get()
        password = self.login_password.get()
        
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        user = session.query(User).filter_by(username=username, password=hashed_password).first()
        
        if user:
            self.current_user = user
            self.load_user_data()
            self.notebook.forget(0)
            self.notebook.forget(0)
            self.notebook.add(self.dashboard_frame, text="Dashboard")
            self.notebook.add(self.profile_frame, text="Profile")
            self.notebook.add(self.settings_frame, text="Settings")
            self.notebook.add(self.app_store_frame, text="App Store")
            self.notebook.add(self.installed_apps_frame, text="Installed Apps")
            self.notebook.add(self.code_editor_frame, text="Code Editor")
            self.notebook.add(self.terminal_frame, text="Terminal")
            self.notebook.add(self.db_migration_frame, text="DB Migration")
            self.notebook.select(self.dashboard_frame)
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")
    
    def signup(self):
        username = self.signup_username.get()
        password = self.signup_password.get()
        email = self.signup_email.get()
        
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        new_user = User(username=username, password=hashed_password, email=email)
        session.add(new_user)
        try:
            session.commit()
            messagebox.showinfo("Success", "Account created successfully")
            self.notebook.select(self.login_frame)
        except:
            session.rollback()
            messagebox.showerror("Error", "Username already exists")
    
   def logout(self):
        self.current_user = None
        for i in range(self.notebook.index("end")-1, -1, -1):
            self.notebook.forget(i)
        self.notebook.add(self.login_frame, text="Login")
        self.notebook.add(self.signup_frame, text="Sign Up")
        self.notebook.select(self.login_frame)
    
    def load_user_data(self):
        self.profile_username_label.config(text=f"Username: {self.current_user[1]}")
        self.profile_email_label.config(text=f"Email: {self.current_user[3]}")
        self.load_installed_apps()
    
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
    
    def install_app(self, app_name):
        self.install_progress.delete('1.0', tk.END)
        self.install_progress.insert(tk.END, f"Installing {app_name}...\n")
        self.master.update()
        
        # Simulating installation process
        install_script = f"""
        echo "Updating package lists..."
        sudo apt-get update
        echo "Installing {app_name}..."
        sudo apt-get install -y {app_name}
        echo "{app_name} installation complete!"
        """
        
        process = subprocess.Popen(['bash', '-c', install_script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                self.install_progress.insert(tk.END, output)
                self.install_progress.see(tk.END)
                self.master.update()
        
        cursor.execute("INSERT INTO installed_apps (user_id, app_name) VALUES (?, ?)",
                       (self.current_user[0], app_name))
        conn.commit()
        
        self.install_progress.insert(tk.END, f"{app_name} has been installed and added to your installed apps list.\n")
        self.load_installed_apps()
    
    def load_installed_apps(self):
        self.installed_apps_list.delete(*self.installed_apps_list.get_children())
        cursor.execute("SELECT app_name FROM installed_apps WHERE user_id=?", (self.current_user[0],))
        installed_apps = cursor.fetchall()
        for app in installed_apps:
            self.installed_apps_list.insert('', 'end', values=(app[0],))

def start_flask_server():
    threading.Thread(target=run_flask, daemon=True).start()
    messagebox.showinfo("Success", "Flask server started on port 5000")

root = tk.Tk()
user_app = UserApp(root)

menu_frame = ttk.Frame(root, padding="10")
menu_frame.pack(side=tk.BOTTOM, fill=tk.X)

ttk.Button(menu_frame, text="Start Flask Server", command=start_flask_server).pack(side=tk.LEFT, padx=5)

root.mainloop()
