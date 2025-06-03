import os
import base64
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet


def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a secret key from the password and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def encrypt_file(file_path: str, password: str):
    """Encrypts a file using the provided password."""
    with open(file_path, 'rb') as f:
        data = f.read()

    salt = os.urandom(16)  # Random salt
    key = derive_key(password, salt)
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data)

    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, 'wb') as f:
        f.write(salt + encrypted_data)  # Prepend salt to encrypted data

    print(f"[+] File encrypted: {encrypted_file_path}")


def decrypt_file(encrypted_file_path: str, password: str):
    """Decrypts a file using the provided password."""
    with open(encrypted_file_path, 'rb') as f:
        salt = f.read(16)  # First 16 bytes are salt
        encrypted_data = f.read()

    key = derive_key(password, salt)
    fernet = Fernet(key)
    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except Exception as e:
        print("[-] Decryption failed. Invalid password or corrupted file.")
        return

    original_file_path = encrypted_file_path.replace(".enc", ".dec")
    with open(original_file_path, 'wb') as f:
        f.write(decrypted_data)

    print(f"[+] File decrypted: {original_file_path}")


def main():
    print("=== File Encryption/Decryption Tool ===")
    choice = input("Do you want to (E)ncrypt or (D)ecrypt a file? ").lower()
    file_path = input("Enter the path to the file: ").strip()
    password = getpass.getpass("Enter password: ")

    if choice == 'e':
        encrypt_file(file_path, password)
    elif choice == 'd':
        decrypt_file(file_path, password)
    else:
        print("[-] Invalid choice. Please select 'E' or 'D'.")


if _name_ == "_main_":
    main()
