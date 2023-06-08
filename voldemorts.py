#!/usr/bin/env python3

import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

import os
import platform
import secrets
import base64
import getpass

files: list[str] = []
dirs: list[str] = []

OS_NAME: str = platform.system()
WD: str = os.getcwd()

def generate_salt(size=16):
    """Generate the salt used for key derivation, 
    `size` is the length of the salt to generate"""
    return secrets.token_bytes(size)


def derive_key(salt, password):
    """Derive the key from the `password` using the passed `salt`"""
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())


def load_salt():
    # load salt from salt.salt file
    return open("salt.salt", "rb").read()


def generate_key(password, salt_size=16, load_existing_salt=False, save_salt=True):
    """
    Generates a key from a `password` and the salt.
    If `load_existing_salt` is True, it'll load the salt from a file
    in the current directory called "salt.salt".
    If `save_salt` is True, then it will generate a new salt
    and save it to "salt.salt"
    """
    if load_existing_salt:
        # load existing salt
        salt = load_salt()
    elif save_salt:
        # generate new salt and save it
        salt = generate_salt(salt_size)
        with open("salt.salt", "wb") as salt_file:
            salt_file.write(salt)
    # generate the key from the salt and the password
    derived_key = derive_key(salt, password)
    # encode it using Base 64 and return it
    return base64.urlsafe_b64encode(derived_key)


def encrypt(filename, key):
    """
    Given a filename (str) and key (bytes), it encrypts the file and write it
    """
    f = Fernet(key)
    with open(filename, "rb") as file:
        # read all file data
        file_data = file.read()
    # encrypt data
    encrypted_data = f.encrypt(file_data)
    # write the encrypted file
    with open(filename, "wb") as file:
        file.write(encrypted_data)


def decrypt(filename, key):
    """
    Given a filename (str) and key (bytes), it decrypts the file and write it
    """
    f = Fernet(key)
    with open(filename, "rb") as file:
        # read the encrypted data
        encrypted_data = file.read()
    # decrypt data
    try:
        decrypted_data = f.decrypt(encrypted_data)
    except cryptography.fernet.InvalidToken:
        return 0
    # write the original file
    with open(filename, "wb") as file:
        file.write(decrypted_data)
    return 1


def filter(path=WD):

    temp_files: list[str] = []
    temp_dirs: list[str] = []

    for element in os.listdir(path=path):

        if element == "voldemorts.py" or element == "salt.salt" or element == "password.txt":
            continue
        
        element = os.path.join(path, element)
            
        if os.path.isfile(element):
            temp_files.append(element)

        if os.path.isdir(element):
            temp_dirs.append(element)

    for i in range(len(temp_files)):
        files.append(temp_files[i])

    for i in range(len(temp_dirs)):
        dirs.append(temp_dirs[i])

    if temp_dirs != []:

        for i in range(len(temp_dirs)):
            filter(os.path.join(path, temp_dirs[i]))

        return dirs, files

    return temp_dirs, temp_files

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="""File Encryptor Script with a Password""")
    parser.add_argument("file", help="File to encrypt/decrypt")
    parser.add_argument("-s", "--salt-size", help="If this is set, a new salt with the passed size is generated", type=int)
    parser.add_argument("-e", "--encrypt", action="store_true",
                        help="Whether to encrypt the file, only -e or -d can be specified.")
    parser.add_argument("-d", "--decrypt", action="store_true",
                        help="Whether to decrypt the file, only -e or -d can be specified.")

    args = parser.parse_args()
    file = args.file

    if args.encrypt:

        try:
            password = getpass.getpass("Enter the password for encryption: ")
        except KeyboardInterrupt:
            print('\n\nMADE BY Muhammed Alkohawaldeh')
            exit()

    elif args.decrypt:

        try:
            password = getpass.getpass("Enter the password you used for encryption: ")
        except KeyboardInterrupt:
            print('\n\nMADE BY Muhammed Alkohawaldeh')
            exit()

    if args.salt_size:
        key = generate_key(password, salt_size=args.salt_size, save_salt=True)
    else:
        key = generate_key(password, load_existing_salt=True)

    encrypt_ = args.encrypt
    decrypt_ = args.decrypt

    if encrypt_ and decrypt_:
        raise TypeError("Please specify whether you want to encrypt the file or decrypt it.")
    elif encrypt_:
        for _file in filter()[1]:
            encrypt(_file, key)
        print("File Encrypted successfully")
    elif decrypt_:
        for _file in filter()[1]:
            if decrypt(_file, key):
                print(f"[{_file.split('/')[-1]}] decrypted successfully")
            else:
                print("Invalid token, most likely the password is incorrect")
                exit(1)
    else:
        raise TypeError("Please specify whether you want to encrypt the file or decrypt it.")

    
