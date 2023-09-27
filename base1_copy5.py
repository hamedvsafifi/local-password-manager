import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
import sqlite3
import bcrypt
from cryptography.fernet import Fernet
import pickle
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import os
import logging
import httplib2

httplib2.debuglevel = 4
logging.getLogger('googleapiclient.discovery').setLevel(logging.DEBUG)

# If modifying these SCOPES, delete the file token.pickle.
SCOPES = ['https://www.googleapis.com/auth/drive.file']

database_path = "D:/front-end web projects/projects/python/local-password-manager/database/password_manager.db"

# Provide the full path for your encryption key file
key_filename = "D:/front-end web projects/projects/python/local-password-manager/database/encryption_key.key"

# Connect to the SQLite database
# If the database does not exist, it will be created
conn = sqlite3.connect(database_path)

# Create a cursor object
c = conn.cursor()

# Create table for users and master password
c.execute('''CREATE TABLE IF NOT EXISTS users
             (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, email TEXT, password TEXT, category TEXT, description TEXT)''')
c.execute('''CREATE TABLE IF NOT EXISTS master_password
             (id INTEGER PRIMARY KEY, password TEXT)''')

root = tk.Tk()
root.geometry("800x600")  # Set the size of the window
root.resizable(False, False)  # Make the window non-resizable

tree = None  # Initialize the 'tree' variable

# Load the key from the file or generate a new one if it doesn't exist
try:
    with open(key_filename, 'rb') as key_file:
        key = key_file.read()
except FileNotFoundError:
    # Generate a new key and save it to the file
    key = Fernet.generate_key()
    with open(key_filename, 'wb') as key_file:
        key_file.write(key)

# Create a cipher suite
cipher_suite = Fernet(key)

def set_master_password():
    global hashed_master
    master_password = simpledialog.askstring("Master Password", "Enter new master password:", show='*')
    if master_password is not None:
        hashed_master = bcrypt.hashpw(master_password.encode('utf-8'), bcrypt.gensalt())
        c.execute("INSERT INTO master_password (password) VALUES (?)", (hashed_master.decode('utf-8'),))
        conn.commit()

def disable_widgets(widgets):
    for widget in widgets:
        widget.config(state=tk.DISABLED)

def enable_widgets(widgets):
    for widget in widgets:
        widget.config(state=tk.NORMAL)

def center_window(window, width, height):
    # Calculate position coordinates for the upper left corner of the window
    position_top = int(window.winfo_screenheight() / 2 - height / 2)
    position_left = int(window.winfo_screenwidth() / 2 - width / 2)

    # Position the window
    window.geometry(f'{width}x{height}+{position_left}+{position_top}')

def check_master_password(event=None):  # Added event parameter to bind Enter key
    global hashed_master
    c.execute("SELECT password FROM master_password WHERE id = 1")
    stored_master_password = c.fetchone()
    if stored_master_password is None:
        set_master_password()
    else:
        hashed_master = stored_master_password[0].encode('utf-8')
        master_password_attempt = master_password_entry.get()
        if bcrypt.checkpw(master_password_attempt.encode('utf-8'), hashed_master):
            enable_widgets(all_widgets)  # Enable all widgets when the correct password is entered
            master_password_window.destroy()  # Close the window when the correct password is entered
        else:
            messagebox.showerror("Error", "Access denied.")

def add_user():
    username = username_entry.get()
    email = email_entry.get()
    password = password_entry.get()
    category = category_entry.get()
    description = description_entry.get()
    
    if username and email and password:
        encrypted_password = cipher_suite.encrypt(password.encode())  # Encrypt the password

        c.execute("INSERT INTO users (username, email, password, category, description) VALUES (?, ?, ?, ?, ?)",
                  (username, email, encrypted_password.decode('utf-8'), category, description))  # Store the encrypted password instead of the plain text password
        conn.commit()
        messagebox.showinfo("Success", "User added.")
        update_categories()
        view_users()  # Call view_users here to refresh the tree view after adding a user
    else:
        messagebox.showerror("Error", "Please fill in all user details.")

def view_users():
    global tree
    if tree is not None:
        for i in tree.get_children():
            tree.delete(i)
        filter_users()  # Call filter_users here to filter the users as soon as you press "View Users"
        update_categories()  # Update the categories each time you view users

def filter_users(*args):
    global tree
    if tree is not None:
        for i in tree.get_children():
            tree.delete(i)
        category_to_filter = category_var.get()
        if category_to_filter == "All":
            c.execute("SELECT id, username, email, password, category, description FROM users")
        else:
            c.execute("SELECT id, username, email, password, category, description FROM users WHERE category=?", (category_to_filter,))
        rows = c.fetchall()
        for row in rows:
            decrypted_password = cipher_suite.decrypt(row[3].encode()).decode()  # Decrypt the password

            tree.insert('', 'end', values=(row[0], row[1], row[2], decrypted_password, row[4], row[5]))  # Display the decrypted password

def update_categories():
    c.execute("SELECT DISTINCT category FROM users")
    categories = [row[0] for row in c.fetchall()]
    categories.insert(0, "All")  # Add "All" as the first option in the dropdown menu
    category_menu['menu'].delete(0, 'end')
    for category in categories:
        category_menu['menu'].add_command(label=category, command=tk._setit(category_var, category))

def authenticate():
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'D:/front-end web projects/projects/python/local-password-manager/credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)
    return build('drive', 'v3', credentials=creds)

def backup(service):
    file_id = '122Y1qVu3vSjrfgi-JQ75npvc7e8nrVuU'
    file_metadata = {'name': 'password_manager.db', 'mimeType': 'application/x-sqlite3'}
    media = MediaFileUpload('D:/front-end web projects/projects/python/local-password-manager/database/password_manager.db',
                            mimetype='application/x-sqlite3',
                            resumable=True)
    file = service.files().update(body=file_metadata,
                                  fileId=file_id,
                                  media_body=media).execute()
    print('File ID: %s' % file.get('id'))
    
    # Create a new tkinter window
    window = tk.Tk()
    window.withdraw()  # Hide the main window

    # Show the messagebox with the message and an OK button
    messagebox.showinfo("Backup Status", "Backup done")

    # Close the tkinter window after the messagebox is closed
    window.destroy()

def perform_backup():
    service = authenticate()
    backup(service)

center_window(root, 800, 600)

username_label = tk.Label(root,text="Username:")
username_label.place(x=20,y=20)
username_entry=tk.Entry(root)
username_entry.place(x=140,y=20)

email_label=tk.Label(root,text="Email:")
email_label.place(x=20,y=60)
email_entry=tk.Entry(root)
email_entry.place(x=140,y=60)

password_label=tk.Label(root,text="Password:")
password_label.place(x=20,y=100)
password_entry=tk.Entry(root, show='*')
password_entry.place(x=140,y=100)

category_label=tk.Label(root,text="Category:")
category_label.place(x=20,y=140)
category_entry=tk.Entry(root)
category_entry.place(x=140,y=140)

description_entry =tk.Label(root, text="description:")
description_entry.place(x=20, y=180)
description_entry=tk.Entry(root)
description_entry.place(x=140, y=180)

add_button = tk.Button(root, text="Add User", state=tk.DISABLED, command=add_user, width=10)  # Set width to 20
add_button.place(x=20, y=220)

view_button = tk.Button(root, text="View Users", state=tk.DISABLED, command=view_users, width=10)  # Set width to 20
view_button.place(x=120, y=220)

backup_button = tk.Button(root, text="back up", state=tk.DISABLED, command=perform_backup, width=10)  # Set width to 20
backup_button.place(x=340, y=220)

category_var = tk.StringVar(root)
category_var.trace('w', filter_users)
category_menu = tk.OptionMenu(root, category_var, '')
category_menu.config(width=10)  # Set width to 20
category_menu.place(x=220, y=217)

frame = tk.Frame(root)
frame.place(x=20, y=260, width=750, height=300)

tree = ttk.Treeview(frame)
scrollbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)

tree.grid(row=0, column=0, sticky='nsew')
scrollbar.grid(row=0, column=1, sticky='ns')

# Create the horizontal scrollbar
x_scrollbar = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)

# Configure the Treeview to update the horizontal scrollbar's position
tree.configure(xscrollcommand=x_scrollbar.set)

# Place the horizontal scrollbar below the Treeview
x_scrollbar.grid(row=1, column=0, sticky='ew')


frame.grid_rowconfigure(0, weight=1)
frame.grid_columnconfigure(0, weight=1)

# # Create a frame with a border
# border_frame = tk.Frame(frame, relief='solid', bd=2)
# border_frame.grid(row=0, column=0, sticky='nsew')

# Create the Treeview inside the frame with the border
# tree = ttk.Treeview(border_frame)
# tree.pack(fill='both', expand=True)  # Use pack instead of grid for the Treeview
tree["columns"]=("ID", "Username", "Email", "Password", "Category", "description")
tree.column("#0", width=0, stretch=tk.NO)
tree.column("ID", anchor=tk.CENTER)
tree.column("Username", anchor=tk.CENTER)
tree.column("Email", anchor=tk.CENTER)
tree.column("Password", anchor=tk.CENTER)  # Added Password column
tree.column("Category", anchor=tk.CENTER)
tree.column("description", anchor=tk.CENTER)

tree.heading("#0",text="",anchor=tk.CENTER)
tree.heading("ID", text="ID",anchor=tk.CENTER)
tree.heading("Username", text="Username",anchor=tk.CENTER)
tree.heading("Email", text="Email",anchor=tk.CENTER)
tree.heading("Password", text="Password",anchor=tk.CENTER)  # Added Password heading
tree.heading("Category", text="Category",anchor=tk.CENTER)
tree.heading("description", text="description",anchor=tk.CENTER)

scrollbar.config(command=tree.yview)
tree.grid(row=0, column=0, sticky='nsew')
scrollbar.grid(row=0, column=1, sticky='ns')


# List of all widgets that should be disabled
all_widgets = [username_entry, email_entry, password_entry, category_entry, add_button, view_button, backup_button, category_menu, description_entry]

disable_widgets(all_widgets)  # Disable all widgets initially

# Create a new Toplevel window for entering the master password
master_password_window = tk.Toplevel(root)  # Create the pop-up window AFTER the main window
master_password_window.geometry("300x100")  # Adjust the size as needed
master_password_window.title("Enter Master Password")
master_password_window.attributes('-topmost', True)
master_password_window.after(1, lambda: master_password_window.attributes('-topmost', False))
center_window(master_password_window, 300, 100)

master_password_label = tk.Label(master_password_window, text="Master Password:")
master_password_label.pack()
master_password_entry = tk.Entry(master_password_window, show='*')
master_password_entry.pack()

check_button = tk.Button(master_password_window, text="Check Master Password", command=check_master_password)
check_button.pack()

root.mainloop()
conn.close()
