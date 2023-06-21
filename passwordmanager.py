import tkinter as tk
from tkinter import messagebox
import bcrypt
import random
import string


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

def generate_strong_password():
    # Function to generate a strong password
    password_length = 12
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(password_length))
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
window.geometry('1000x500')

username_label = tk.Label(window, text="Username:")
username_label.pack()
username_entry = tk.Entry(window)
username_entry.pack()

password_label = tk.Label(window, text="Password:")
password_label.pack()
password_entry = tk.Entry(window, show="*")
password_entry.pack()

store_button = tk.Button(window, text="Store Password", command=store_password)
store_button.pack()

authenticate_button = tk.Button(window, text="Authenticate", command=authenticate_user)
authenticate_button.pack()

crack_time_button = tk.Button(window, text="Check Crack Time", command=check_crack_time)
crack_time_button.pack()

suggest_password_button = tk.Button(window, text="Suggest Strong Password", command=suggest_strong_password)
suggest_password_button.pack()

window.mainloop()
