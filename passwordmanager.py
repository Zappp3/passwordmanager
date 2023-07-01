import tkinter as tk
from tkinter import messagebox
import bcrypt
import random
import string
from tkinter import *

def check_password_strength(password):
    if len(password) < 8:
        return False
    has_lowercase = False
    has_uppercase = False
    has_digit = False
    has_special = False

    for char in password:
        if char.islower():
            has_lowercase = True
        elif char.isupper():
            has_uppercase = True
        elif char.isdigit():
            has_digit = True
        else:
            has_special = True

    return has_lowercase and has_uppercase and has_digit and has_special

def store_password():
    username = username_entry.get()
    password = password_entry.get()

    if check_password_strength(password):
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
        with open('passwords.txt', 'a') as file:
            file.write(f"Username: {username}\n")
            file.write(f"Hashed Password: {hashed_password.decode()}\n")
            file.write("-" * 20 + "\n")
        messagebox.showinfo("Success", "Password stored successfully.")
    else:
        messagebox.showwarning("Weak Password", "Please choose a stronger password.")

def generate_strong_password(length=10):
    while True:
        password = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=length))
        if check_password_strength(password):
            return password

def suggest_strong_password():
    password = generate_strong_password()
    password_entry.delete(0, tk.END)
    password_entry.insert(tk.END, password)
    messagebox.showinfo("Suggested Password", f"Your suggested password is:\n\n{password}")

def authenticate_user():
    username = username_entry.get()
    password = password_entry.get()

    stored_hashed_password = None
    with open('passwords.txt', 'r') as file:
        lines = file.readlines()
        for i, line in enumerate(lines):
            if line.strip() == f"Username: {username}":
                stored_hashed_password = lines[i + 1].replace("Hashed Password: ", "").strip()
                break

    if stored_hashed_password is not None and bcrypt.checkpw(password.encode(), stored_hashed_password.encode()):
        messagebox.showinfo("Authentication", "Authentication successful")
    else:
        messagebox.showwarning("Authentication", "Authentication failed")

def estimate_crack_time(password):
    crack_time = 0
    characters = 0
    lowercase = 26
    uppercase = 26
    digits = 10
    special = 33
    total = lowercase + uppercase + digits + special

    if password:
        characters = len(password)
        combinations = total ** characters
        crack_time = combinations / 2_000_000_000

    return crack_time

def check_crack_time():
    password = password_entry.get()
    crack_time = estimate_crack_time(password)
    messagebox.showinfo("Crack Time", f"The estimated time to crack the password is approximately {crack_time:.2f} seconds.")

window = tk.Tk()
window.title("Password Manager")
window.geometry('800x400')
photo=PhotoImage(file="edited.png")
photo_label=Label(image=photo)
photo_label.place(x=0, y=0, relwidth=1, relheight=1)
username_label = tk.Label(window, text="Username:",background='black',fg='white')
username_entry = tk.Entry(window)
password_label = tk.Label(window, text="Password:",background='black',fg='white')
password_entry = tk.Entry(window, show="*")

username_label.grid(row=1, column=0, sticky="E",pady=10)
username_entry.grid(row=1, column=1,pady=10)
password_label.grid(row=2, column=0, sticky="E",pady=10)
password_entry.grid(row=2, column=1,pady=10)

store_button = tk.Button(window, text="Store Password", command=store_password)
suggest_password_button = tk.Button(window, text="Suggest Strong Password", command=suggest_strong_password)
crack_time_button = tk.Button(window, text="Check Crack Time", command=check_crack_time)
authenticate_button = tk.Button(window, text="Authenticate", command=authenticate_user)

store_button.grid(row=3, column=0,pady=10)
suggest_password_button.grid(row=3, column=1, pady=10)
crack_time_button.grid(row=3, column=2,  pady=10)
authenticate_button.grid(row=4, column=0, columnspan=3,  pady=10)

window.grid_rowconfigure(0, weight=1)
window.grid_rowconfigure(6, weight=1)
window.grid_columnconfigure(0, weight=1)
window.grid_columnconfigure(2, weight=1)

window.mainloop()
