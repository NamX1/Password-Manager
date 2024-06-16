import bcrypt
import os
import base64
import getpass
import json
import string
import random

from cryptography.fernet import Fernet
from utils.crint import *

def generate_key():
    return base64.urlsafe_b64encode(os.urandom(32))

def load_or_create_key():
    key_path = "secret.key"

    if os.path.exists(key_path):
        with open(key_path, "rb") as file:
            key = file.read()
            return key
    else:
        key = generate_key()
        with open(key_path, "wb") as file:
            file.write(key)
            return key

def encrypt_data(data, key):
    fernet = Fernet(key)
    return fernet.encrypt(data.encode())

def decrypt_data(token, key):
    fernet = Fernet(key)
    return fernet.decrypt(token).decode()

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

def generate_password(length):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

def check_password_strength(password):
    if len(password) < 8:
        return Crint.info(f"{password} is weak.")
    if not any(char.isdigit() for char in password):
        return Crint.info(f"{password} is moderate.")
    if not any(char.islower() for char in password):
        return Crint.info(f"{password} is moderate.")
    if not any(char.isupper() for char in password):
        return Crint.info(f"{password} is moderate.")
    if not any(char in string.punctuation for char in password):
        return Crint.info(f"{password} is moderate.")
    return Crint.info(f"{password} is strong.")

def store_password(data, key):
    with open("passwords.json", "w") as file:
        encrypted_data = encrypt_data(json.dumps(data), key)
        file.write(encrypted_data.decode('utf-8'))

def load_passwords(key):
    if not os.path.exists("passwords.json"):
        return {}
    with open("passwords.json", "r") as file:
        encrypted_data = file.read().encode('utf-8')
        data = decrypt_data(encrypted_data, key)
        return json.loads(data)

class PasswordManager:
    def __init__(self, master_password):
        self.key = load_or_create_key()
        self.master_password_hashed = hash_password(master_password)
        self.passwords = load_passwords(self.key)

    def authenticate(self, master_password):
        return check_password(master_password, self.master_password_hashed)

    def add_password(self, service, username, password):
        self.passwords[service] = {
            "username": username,
            "password": encrypt_data(password, self.key).decode('utf-8')
        }
        store_password(self.passwords, self.key)

    def retrieve_password(self, service):
        if service in self.passwords:
            username = self.passwords[service]["username"]
            encrypted_password = self.passwords[service]["password"]
            password = decrypt_data(encrypted_password.encode('utf-8'), self.key)
            return username, password
        return None, None

    def update_password(self, service, new_password):
        if service in self.passwords:
            self.passwords[service]["password"] = encrypt_data(new_password, self.key).decode('utf-8')
            store_password(self.passwords, self.key)

    def delete_password(self, service):
        if service in self.passwords:
            del self.passwords[service]
            store_password(self.passwords, self.key)

# Main Program
def main():
    master_password = getpass.getpass("Enter your master password: ")
    manager = PasswordManager(master_password)

    if not manager.authenticate(master_password):
        Crint.error("Invalid master password.")
        return

    while True:
        Crint.info("\nPassword Manager Menu:\n1. Add Password\n2. Retrieve Password\n3. Update Password\n4. Delete Password\n5. Generate Password\n6. Check Password Strength\n7. Exit")
        choice = Crint.prompt("Enter your choice: ")

        if choice == "1":
            service = Crint.prompt("Enter the service name: ")
            username = Crint.prompt("Enter the username: ")
            password = getpass.getpass("Enter the password: ")
            manager.add_password(service, username, password)
            Crint.success("Password added successfully.")
        elif choice == "2":
            service = Crint.prompt("Enter the service name: ")
            username, password = manager.retrieve_password(service)
            if password:
                Crint.success(f"Username: {username}\nPassword for {service}: {password}")
            else:
                Crint.error("Service not found.")
        elif choice == "3":
            service = Crint.prompt("Enter the service name: ")
            new_password = getpass.getpass("Enter the new password: ")
            manager.update_password(service, new_password)
            Crint.success("Password updated successfully.")
        elif choice == "4":
            service = Crint.prompt("Enter the service name: ")
            manager.delete_password(service)
            Crint.success("Password deleted successfully.")
        elif choice == "5":
            length = int(Crint.prompt("Enter the password length: "))
            if length is None:
                generated_password = generate_password(length)
                Crint.success(f"Generated Password: {generated_password}")
        elif choice == "6":
            password = getpass.getpass("Enter the password to check: ")
            strength = check_password_strength(password)
            Crint.success(f"Password Strength: {strength}")
        elif choice == "7":
            Crint.info("Exiting Password Manager.")
            break
        else:
            Crint.error("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
