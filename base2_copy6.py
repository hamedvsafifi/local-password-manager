import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
import sqlite3
import bcrypt
from cryptography.fernet import Fernet
import pickle
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from googleapiclient.http import MediaIoBaseDownload
from googleapiclient.errors import HttpError
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

import os
import logging
import httplib2
import pyperclip
from PIL import Image, ImageTk

httplib2.debuglevel = 4
logging.getLogger('googleapiclient.discovery').setLevel(logging.DEBUG)

# If modifying these SCOPES, delete the file token.pickle.
SCOPES = ['https://www.googleapis.com/auth/drive.file']

database_path = "database/password_manager.db"

# Provide the full path for your encryption key file
key_filename = "database/encryption_key.key"

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
root.title("password manager")
root.geometry("600x600")  # Set the size of the window
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

def reset_master_password():
    global hashed_master
    master_password = simpledialog.askstring("Master Password", "Enter new master password:", show='*')
    if master_password is not None:
        hashed_master = bcrypt.hashpw(master_password.encode('utf-8'), bcrypt.gensalt())
        c.execute("UPDATE master_password SET password = ? WHERE id = 1", (hashed_master.decode('utf-8'),))
        conn.commit()

def disable_widgets(widgets):
    for widget in widgets:
        widget.config(state=tk.DISABLED)

def enable_widgets(widgets):
    for widget in widgets:
        widget.config(state=tk.NORMAL)

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

def on_mainwindow_click(event):
        if master_password_window is not None and master_password_window.winfo_exists():
            master_password_window.attributes('-topmost', True)
            for _ in range(2):  # flash 5 times
                master_password_window.withdraw()
                root.after(80)  # wait 200ms
                root.update()
                master_password_window.deiconify()
                root.after(80)  # wait 200ms
                root.update()

def add_user():
    username = username_entry.get()
    email = email_entry.get()
    password = password_entry.get()
    category = category_entry.get()
    description = description_entry.get("1.0", "end")
    
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

def remove_user():
    selected_items = tree.selection()  # Get all selected items
    if not selected_items:
        messagebox.showerror("Error", "Please select one or more users to remove.")
        return

    confirm = messagebox.askyesno("Confirm Removal", "Are you sure you want to remove the selected user(s)?")
    if not confirm:
        return

    for selected_item in selected_items:
        user_id = tree.item(selected_item, 'values')[0]  # Get the user's ID
        if user_id is not None:
            c.execute("DELETE FROM users WHERE id=?", (user_id,))
    
    conn.commit()
    view_users()  # Refresh the user list after removal
    messagebox.showinfo("Success", "User(s) removed.")

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
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)
    return build('drive', 'v3', credentials=creds)

def copy_account():
    selected_item = tree.selection()[0]  # Get the selected item
    account_details = tree.item(selected_item)['values']  # Get the account details

    # Create a list of the column names in the same order as in the tree
    column_names = ["id", "username", "email", "password", "category", "description"]

    # Combine the column names and values into a dictionary
    account_dict = dict(zip(column_names, account_details))

    # Add quotes around the description
    account_dict["description"] = f'"{account_dict["description"]}"'

    # Convert the dictionary to a string with the format "key: value"
    account_details_str = '\n'.join(f"{key}: {value}" for key, value in account_dict.items())

    pyperclip.copy(account_details_str)  # Copy the string to the clipboard

def check_file_in_drive():
    # Call the Drive v3 API
    service = authenticate()
    filename = 'password_manager.db'
    try:
        # Call the Drive v3 API
        results = service.files().list(
            q=f"name='{filename}' and trashed=false",
            fields="files(id, name)").execute()
        items = results.get('files', [])

        # Print number of files found
        print(f"Found {len(items)} files with the name '{filename}'.")

        # If the file exists, return its id; otherwise, return None
        return items[0]['id'] if items else None

    except Exception as e:
        # Print any errors that occur
        print(f"An error occurred: {e}")

def backup(service, file_id=check_file_in_drive()):
    # File name you want to backup
    file_name = 'password_manager.db'
    
    # File metadata and media for upload
    file_metadata = {'name': file_name, 'mimeType': 'application/x-sqlite3'}
    media = MediaFileUpload('database/password_manager.db',
                            mimetype='application/x-sqlite3',
                            resumable=True)
    
    if file_id:
        # If file ID is provided, try to update the file
        try:
            service.files().get(fileId=file_id).execute()
            print('File found. Updating...')
            file = service.files().update(body=file_metadata,
                                          fileId=file_id,
                                          media_body=media).execute()
            message = "File updated"
        except HttpError as error:
            print('File not found. Uploading...')
            # File doesn't exist, so we upload it
            file = service.files().create(body=file_metadata,
                                          media_body=media).execute()
            message = "File uploaded"
    else:
        # If no file ID is provided, upload a new file
        print('Uploading...')
        file = service.files().create(body=file_metadata,
                                      media_body=media).execute()
        message = "File uploaded"
    
    print('File ID: %s' % file.get('id'))
    
    # Create a new tkinter window
    window = tk.Tk()
    window.withdraw()  # Hide the main window

    # Show the messagebox with the message and an OK button
    messagebox.showinfo("Backup Status", message)

    # Close the tkinter window after the messagebox is closed
    window.destroy()

def perform_backup():
    service = authenticate()
    backup(service)

def download_backup(service,file_id=check_file_in_drive()):
    # Get file's metadata
    file_metadata = service.files().get(fileId=file_id).execute()
    # Get file's name from metadata
    filename = file_metadata['name']
    filepath = os.path.join('database', filename)

    request = service.files().get_media(fileId=file_id)
    fh = open(filepath, 'wb')
    downloader = MediaIoBaseDownload(fh, request)
    done = False
    while done is False:
        status, done = downloader.next_chunk()
        print("Download %d%%." % int(status.progress() * 100))
        # Create a new tkinter window
    window = tk.Tk()
    window.withdraw()  # Hide the main window

    # Show the messagebox with the message and an OK button
    messagebox.showinfo("Backup Status", "download done")

    # Close the tkinter window after the messagebox is closed
    window.destroy()

def perform_download():
    service = authenticate()
    download_backup(service)

root.bind("<Button-1>", on_mainwindow_click)

username_label = tk.Label(root,text="Username:")
username_label.place(x=20,y=20)
username_entry=tk.Entry(root)
username_entry.place(x=100,y=20)


email_label=tk.Label(root,text="Email:")
email_label.place(x=40,y=60)
email_entry=tk.Entry(root)
email_entry.place(x=100,y=60)

password_label=tk.Label(root,text="Password:")
password_label.place(x=20,y=100)
password_entry=tk.Entry(root, show='*')
password_entry.place(x=100,y=100)


category_label=tk.Label(root,text="Category:")
category_label.place(x=22,y=140)
category_entry=tk.Entry(root)
category_entry.place(x=100,y=140)


description_label=tk.Label(root, text="description:")
description_label.place(x=240, y=20)
description_entry=tk.Text(root, height=6, width=30)
description_entry.place(x=300, y=50)  # Adjust x and y as needed

add_button = tk.Button(root, text="Add User", state=tk.DISABLED, command=add_user, width=15)  # Set width to 20
add_button.place(x=20, y=180)

remove_button = tk.Button(root, text="Remove User", state=tk.DISABLED, command=remove_user, width=15)
remove_button.place(x=280, y=180)

view_button = tk.Button(root, text="View Users", state=tk.DISABLED, command=view_users, width=15)  # Set width to 20
view_button.place(x=150, y=180)

copy_button = tk.Button(root, text="Copy Account", command=copy_account, width=15)
copy_button.pack()
copy_button.place(x=20, y=220)  # Adjust x and y as needed

backup_button = tk.Button(root, text="back up", state=tk.DISABLED, command=perform_backup, width=15)  # Set width to 20
backup_button.place(x=150, y=220)

download_button = tk.Button(root, text="download backup", state=tk.DISABLED, command=perform_download, width=15)  # Set width to 20
download_button.place(x=280, y=220)

reset_master_button = tk.Button(root, text="reset password", state=tk.DISABLED, command=reset_master_password, width=15)
reset_master_button.place(x=410, y=180)

category_var = tk.StringVar(root)
category_var.trace('w', filter_users)
category_menu = tk.OptionMenu(root, category_var, '')
category_menu.config(width=12)  # Set width to 20
category_menu.place(x=410, y=217)

frame = tk.Frame(root)
frame.place(x=20, y=260, width=550, height=300)

tree = ttk.Treeview(frame)

frame.grid_rowconfigure(0, weight=1)
frame.grid_columnconfigure(0, weight=1)

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

tree.grid(row=0, column=0, sticky='nsew')

y_scrollbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
tree.configure(yscrollcommand=y_scrollbar.set)
y_scrollbar.grid(row=0, column=1, sticky='ns')

x_scrollbar = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
tree.configure(xscrollcommand=x_scrollbar.set)
x_scrollbar.grid(row=1, column=0, sticky='ew')


# List of all widgets that should be disabled
all_widgets = [username_entry, email_entry, password_entry, category_entry, add_button, remove_button, view_button, backup_button, category_menu, description_entry, copy_button, download_button , reset_master_button]

disable_widgets(all_widgets)  # Disable all widgets initially

# Create a new Toplevel window for entering the master password
master_password_window = tk.Toplevel(root)  # Create the pop-up window AFTER the main window
master_password_window.geometry("300x100")  # Adjust the size as needed
master_password_window.resizable(False, False)  # Make the window non-resizable
master_password_window.title("Enter Master Password")
master_password_window.attributes('-topmost', True)
master_password_window.after(1, lambda: master_password_window.attributes('-topmost', False))

master_password_label = tk.Label(master_password_window, text="Master Password:")
master_password_label.pack()
master_password_label.place(x=85,y=15)
master_password_entry = tk.Entry(master_password_window, show='*')
master_password_entry.pack()
master_password_entry.place(x=84,y=35)

check_button = tk.Button(master_password_window, text="Check Master Password", command=check_master_password)
check_button.pack()
check_button.place(x=80,y=60)

def customization():
    # Open the image file
    img = Image.open('icons/Untitled-1.png')
    # Resize the image to new dimensions
    resized_img = img.resize((128, 128), Image.LANCZOS)
    # Create PhotoImage object from the resized image
    photo_img = ImageTk.PhotoImage(resized_img)
    # Set the window icon
    root.iconphoto(False, photo_img)
    root.configure(bg='#323232')  # Set the background color of the main window #forecolor #FD6C58 #231929
    master_password_window.iconphoto(False, photo_img)
    master_password_window.configure(bg='#323232')
                                     
    username_label.configure(bg='#323232', fg='#FD6C58')
    email_label.configure(bg='#323232', fg='#FD6C58')
    password_label.configure(bg='#323232', fg='#FD6C58')
    category_label.configure(bg='#323232', fg='#FD6C58')
    description_label.configure(bg='#323232', fg='#FD6C58')
    master_password_label.configure(bg='#323232', fg='#FD6C58')

    username_entry.configure(foreground="#FFFFFF", background="#4A4A4A")
    email_entry.configure(foreground="#FFFFFF", background="#4A4A4A")
    password_entry.configure(foreground="#FFFFFF", background="#4A4A4A")
    category_entry.configure(foreground="#FFFFFF", background="#4A4A4A")
    description_entry.configure(foreground="#FFFFFF", background="#4A4A4A")
    master_password_entry.configure(foreground="#FFFFFF", background="#4A4A4A")

    add_button.configure(foreground="#FFFFFF", background="#61575B")
    copy_button.configure(foreground="#FFFFFF", background="#61575B")
    view_button.configure(foreground="#FFFFFF", background="#61575B")
    check_button.configure(foreground="#FFFFFF", background="#61575B")
    remove_button.configure(foreground="#FFFFFF", background="#61575B")
    backup_button.configure(foreground="#FFFFFF", background="#61575B")
    download_button.configure(foreground="#FFFFFF", background="#61575B")
    category_menu.configure(foreground="#FFFFFF", background="#61575B")
    reset_master_button.configure(foreground="#FFFFFF", background="#61575B")

customization()
root.mainloop()
conn.close()


