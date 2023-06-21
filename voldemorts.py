#!/usr/bin/env python3

import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

import os
import typing
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
        encrypted_data: bytes = file.read()
    # decrypt data
    try:
        decrypted_data: bytes = f.decrypt(encrypted_data)
    except cryptography.fernet.InvalidToken:
        return 0
    # write the original file
    with open(filename, "wb") as file:
        file.write(decrypted_data)
    return 1

def not_around(gpath, home_path) -> list[str]:
    dirs_for_filter: list[str] = []

    for root, Gdir, Gfiles in os.walk(home_path):
            for i in range(len(Gdir)):
                if Gdir[i] in [gpath.split('/')[-1]]:

                    gpath: str = root[0:] + '/' + Gdir[i]
                    print(gpath)
                    prossesed_copy_path: str = gpath
                    dirs_for_filter.append(prossesed_copy_path)
    return dirs_for_filter


def filter(arg_path: str =WD, *, is_around: bool =True, skipped: typing.Union[None, list[str]] =None):

    path = arg_path
    path_ = path

    print("path from start: " + path)
    
    input_copy_path: str = path

    temp_files: list[str] = []
    temp_dirs: list[str] = []
    repeted_dirs: list[str] = []

    if not is_around:
        repeted_dirs = not_around(path, '/home')
        path_ = repeted_dirs

    if len(path_) > 1:
        print(f"""There a {len(repeted_dirs)} file that have the same name of {input_copy_path}.""")
        i: int = 1
        for dir in repeted_dirs:
            if i == 1:
                print(f"\n\n    {i}. The {input_copy_path} in [  {repeted_dirs[i]}  ] folder")
                i += 1
                continue
            print(f"    {i}. The {input_copy_path} in [  {repeted_dirs[i - 2]}  ] folder")
            i += 1
        print(f"    {i}. All of them\n")
        try:
            response: int = int(input('Choose one of the available options by passing it\'s number: '))
            response -= 1
        except ValueError:
            print("This is not in the valed.")

        if response == len(repeted_dirs) + 1:
            print("This future is not available yat.")  #   Make this dream in reality :) 
            exit(1)

        path_ = repeted_dirs[response]

    for element in os.listdir(path=path_):

        if skipped != None:
            if element in [file_ for file_ in skipped]:  # ["voldemorts.py", "salt.salt", "password.txt"]
                continue

        if element in ["voldemorts.py", "salt.salt"]:
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
    parser.add_argument("-i", "--is-around", help="If is around, the tool will encrypt/decrypt all the files that is with it in the same folder", type=bool)
    parser.add_argument("-k", "--skipped", help="If there is any file you want to ignored it", type=list[str])

    args = parser.parse_args()
    file = args.file

    if args.encrypt:

        try:
            password: str = getpass.getpass("Enter the password for encryption: ")
        except KeyboardInterrupt:
            print('\n\nMADE BY Muhammed Alkohawaldeh')
            exit(1)

    elif args.decrypt:

        try:
            password: str = getpass.getpass("Enter the password you used for encryption: ")
        except KeyboardInterrupt:
            print('\n\nMADE BY Muhammed Alkohawaldeh')
            exit(1)

    if args.salt_size:
        key: bytes = generate_key(password, salt_size=args.salt_size, save_salt=True)
    else:
        key: bytes = generate_key(password, load_existing_salt=True)

    encrypt_ = args.encrypt
    decrypt_ = args.decrypt

    if encrypt_ and decrypt_:
        raise TypeError("Please specify whether you want to encrypt the file or decrypt it.")
    elif encrypt_:
        if args.is_around:
            
            if args.skipped:
                for _file in filter(file, is_around=True, skipped=args.skipped)[1]:
                    encrypt(_file, key)

            for _file in filter(file, is_around=True, skipped=None)[1]:
                encrypt(_file, key)

        elif args.skipped:
            for _file in filter(file, is_around=False, skipped=args.skipped)[1]:
                    encrypt(_file, key)
        else:
            for _file in filter(file, is_around=False, skipped=None)[1]:
                    encrypt(_file, key)

        print("File Encrypted successfully")

    elif decrypt_:
        if args.is_around:
            
            if args.skipped:
                            for _file in filter(file, is_around=True, skipped=args.skipped)[1]:
                                if decrypt(_file, key):
                                    print(f"[{_file.split('/')[-1]}] decrypted successfully")
                                else:
                                    print("Invalid token, most likely the password is incorrect")
                                    exit(1)

            for _file in filter(file, is_around=True, skipped=None)[1]:
                    if decrypt(_file, key):
                        print(f"[{_file.split('/')[-1]}] decrypted successfully")
                    else:
                        print("Invalid token, most likely the password is incorrect")
                        exit(1)
                    
        elif args.skipped:
            for _file in filter(file, is_around=False, skipped=args.skipped)[1]:
                    if decrypt(_file, key):
                        print(f"[{_file.split('/')[-1]}] decrypted successfully")
                    else:
                        print("Invalid token, most likely the password is incorrect")
                        exit(1)
        else:
            for _file in filter(file, is_around=False, skipped=None)[1]:
                    if decrypt(_file, key):
                        print(f"[{_file.split('/')[-1]}] decrypted successfully")
                    else:
                        print("Invalid token, most likely the password is incorrect")
                        exit(1)
    else:
        raise TypeError("Please specify whether you want to encrypt the file or decrypt it.")

    # password = 'moh'

    # key = generate_key(password, salt_size=128, save_salt=True)

    # for _file in filter('people info', is_around=False, skipped=None)[1]:
    #         encrypt(_file, key)

    # print("File Encrypted successfully")