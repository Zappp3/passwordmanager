import tkinter as tk
from tkinter import messagebox
import bcrypt
import random
import string
import datetime
from tkinter import *
import mysql.connector

MAX_USERS = 10

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

    if not (has_lowercase and has_uppercase and has_digit and has_special):
        return False

    try:
        connection = mysql.connector.connect(
            host="localhost",
            user="user",
            password="password",
            database="db"
        )
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM 200_passwords WHERE password = %s", (password,))
        result = cursor.fetchone()
        cursor.close()
        connection.close()
        if result and result[0] > 0:
            return False
    except mysql.connector.Error as error:
        print("Error while connecting to MySQL:", error)

    return True

def is_username_taken(username):
    try:
        connection = mysql.connector.connect(
            host="localhost",
            user="user",
            password="password",
            database="db"
        )
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM passwords WHERE username = %s", (username,))
        result = cursor.fetchone()
        cursor.close()
        connection.close()
        if result:
            return True
        else:
            return False
    except mysql.connector.Error as error:
        print("Error while connecting to MySQL:", error)
        return False

def check_password_last_changed(username):
    last_changed = None
    try:
        connection = mysql.connector.connect(
            host="localhost",
            user="user",
            password="password",
            database="db"
        )
        cursor = connection.cursor()
        cursor.execute("SELECT last_changed FROM passwords WHERE username = %s", (username,))
        result = cursor.fetchone()
        cursor.close()
        connection.close()
        if result:
            last_changed = result[0]
        return last_changed
    except mysql.connector.Error as error:
        print("Error while connecting to MySQL:", error)
        return last_changed

def get_user_count():
    count = 0
    try:
        connection = mysql.connector.connect(
            host="localhost",
            user="user",
            password="password",
            database="db"
        )
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM passwords")
        result = cursor.fetchone()
        cursor.close()
        connection.close()
        if result:
            count = result[0]
        return count
    except mysql.connector.Error as error:
        print("Error while connecting to MySQL:", error)
        return count

def store_password():
    username = username_entry.get()
    password = password_entry.get()

    user_count = get_user_count()
    if user_count >= MAX_USERS:
        messagebox.showwarning("User Limit Reached", f"The maximum number of users ({MAX_USERS}) has been reached. Please try again later.")
    elif is_username_taken(username):
        messagebox.showwarning("Username Taken", "The username you entered is already taken. Please choose a different username.")
    elif check_password_strength(password):
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
        try:
            connection = mysql.connector.connect(
                host="localhost",
                user="user",
                password="password",
                database="db"
            )
            cursor = connection.cursor()
            insert_query = "INSERT INTO passwords (username, hashed_password, last_changed) VALUES (%s, %s, %s)"
            current_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute(insert_query, (username, hashed_password.decode(), current_date))
            connection.commit()
            cursor.close()
            connection.close()
            messagebox.showinfo("Success", "Password stored successfully.")
        except mysql.connector.Error as error:
            print("Error while connecting to MySQL:", error)
    else:
        messagebox.showwarning("Weak Password", "Please choose a stronger password with a combination of uppercase, lowercase, digits, and special characters.")


def update_password():
    username = username_entry.get()
    password = password_entry.get()

    if not is_username_taken(username):
        messagebox.showwarning("Username Not Found", "Username not found. Please enter a valid username.")
    elif not check_password_strength(password):
        messagebox.showwarning("Weak Password", "Please choose a stronger password with a combination of uppercase, lowercase, digits, and special characters.")
    else:
        stored_hashed_password = None
        try:
            connection = mysql.connector.connect(
                host="localhost",
                user="user",
                password="password",
                database="db"
            )
            cursor = connection.cursor()
            cursor.execute("SELECT hashed_password FROM passwords WHERE username = %s", (username,))
            result = cursor.fetchone()
            cursor.close()
            connection.close()
            if result:
                stored_hashed_password = result[0]
        except mysql.connector.Error as error:
            print("Error while connecting to MySQL:", error)

        if bcrypt.checkpw(password.encode(), stored_hashed_password.encode()):
            messagebox.showwarning("Password Reuse", "The updated password cannot be the same as the previously used password. Please choose a different password.")
        else:
            hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
            try:
                connection = mysql.connector.connect(
                    host="localhost",
                    user="user",
                    password="password",
                    database="db"
                )
                cursor = connection.cursor()
                update_query = "UPDATE passwords SET hashed_password = %s, last_changed = %s WHERE username = %s"
                current_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                cursor.execute(update_query, (hashed_password.decode(), current_date, username))
                connection.commit()
                cursor.close()
                connection.close()
                messagebox.showinfo("Success", "Password updated successfully.")
            except mysql.connector.Error as error:
                print("Error while connecting to MySQL:", error)


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
    last_changed = None
    try:
        connection = mysql.connector.connect(
            host="localhost",
            user="user",
            password="password",
            database="db"
        )
        cursor = connection.cursor()
        cursor.execute("SELECT hashed_password, last_changed FROM passwords WHERE username = %s", (username,))
        result = cursor.fetchone()
        cursor.close()
        connection.close()
        if result:
            stored_hashed_password = result[0]
            last_changed = result[1]
    except mysql.connector.Error as error:
        print("Error while connecting to MySQL:", error)

    if is_username_taken(username) and bcrypt.checkpw(password.encode(), stored_hashed_password.encode()):

        current_time = datetime.datetime.now()
        time_since_last_changed = current_time - last_changed

        if time_since_last_changed.days >= 1:
            messagebox.showwarning("Change Password", "Your password has expired. Please change your password.")
        else:
            messagebox.showinfo("Authentication", "Authentication successful")
    elif is_username_taken(username):
        messagebox.showwarning("Authentication", "Authentication failed. Incorrect password.")
    else:
        messagebox.showwarning("Authentication", "Authentication failed. Username not found.")


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

def delete_credentials():
    username = username_entry.get()

    if not is_username_taken(username):
        messagebox.showwarning("Username Not Found", "Username not found. Please enter a valid username.")
    else:
        try:
            connection = mysql.connector.connect(
                host="localhost",
                user="user",
                password="password",
                database="db"
            )
            cursor = connection.cursor()
            delete_query = "DELETE FROM passwords WHERE username = %s"
            cursor.execute(delete_query, (username,))
            connection.commit()
            cursor.close()
            connection.close()
            messagebox.showinfo("Success", "Username and password deleted successfully.")
        except mysql.connector.Error as error:
            print("Error while connecting to MySQL:", error)

window = tk.Tk()
window.title("Password Manager")
window.geometry('800x400')
photo = PhotoImage(file="edited.png")
photo_label = Label(image=photo)
photo_label.place(x=0, y=0, relwidth=1, relheight=1)
username_label = tk.Label(window, text="Username:", background='black', fg='white')
username_entry = tk.Entry(window)
password_label = tk.Label(window, text="Password:", background='black', fg='white')
password_entry = tk.Entry(window, show="*")

username_label.grid(row=1, column=0, sticky="E", pady=10)
username_entry.grid(row=1, column=1, pady=10)
password_label.grid(row=2, column=0, sticky="E", pady=10)
password_entry.grid(row=2, column=1, pady=10)

store_button = tk.Button(window, text="Store Password", command=store_password)
update_button = tk.Button(window, text="Update Password", command=update_password)
suggest_password_button = tk.Button(window, text="Suggest Strong Password", command=suggest_strong_password)
crack_time_button = tk.Button(window, text="Check Crack Time", command=check_crack_time)
authenticate_button = tk.Button(window, text="Authenticate", command=authenticate_user)
delete_button = tk.Button(window, text="Delete Credentials", command=delete_credentials)

delete_button.grid(row=4, column=0, pady=10)
store_button.grid(row=3, column=0, pady=10)
update_button.grid(row=4, column=2, columnspan=1, pady=10)
suggest_password_button.grid(row=3, column=1, pady=10)
crack_time_button.grid(row=3, column=2, pady=10)
authenticate_button.grid(row=4, column=1, columnspan=1, pady=10)

window.grid_rowconfigure(0, weight=1)
window.grid_rowconfigure(6, weight=1)
window.grid_columnconfigure(0, weight=1)
window.grid_columnconfigure(2, weight=1)

window.mainloop()
