#!/usr/bin/env python3

import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from rich.progress import track

import os
import typing
import platform
import hashlib
import secrets
import base64
import getpass
import colorama
import threading
import datetime
import time
import sys

print(f"""{colorama.Fore.CYAN}                                                     
            (   (                              )     
 (   (      )\  )\ )   (     )         (    ( /(     
 )\  )\ (  ((_)(()/(  ))\   (      (   )(   )\())(   
((_)((_))\  _   ((_))/((_)  )\  '  )\ (()\ (_))/ )\  
\ \ / /((_)| |  _| |(_))  _((_))  ((_) ((_)| |_ ((_) 
 \ V // _ \| |/ _` |/ -_)| '  \()/ _ \| '_||  _|(_-< 
  \_/ \___/|_|\__,_|\___||_|_|_| \___/|_|   \__|/__/ 
                                                     
{colorama.Fore.GREEN}A powrfull encryption tool made By {colorama.Fore.BLUE}Muhammed Alkohawaldeh{colorama.Fore.RESET}""")

def sprint(text, second=0.03):
    for line in text + '\n':
        sys.stdout.write(line)
        sys.stdout.flush()
        time.sleep(second)

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


def load_salt(filename):
    # load salt from salt.salt file
    return open(f".{filename}.salt", "rb").read()


def generate_key(password, salt_size=16, load_existing_salt=False, save_salt=True, filename='ex'):
    """
    Generates a key from a `password` and the salt.
    If `load_existing_salt` is True, it'll load the salt from a file
    in the current directory called "salt.salt".
    If `save_salt` is True, then it will generate a new salt
    and save it to "salt.salt"
    """
    filename = hashlib.md5((filename+'sdfwlkfiowprgnvEFJVO;HIbvioenyeyvgryw3weqvuincmcoqim').encode()).hexdigest()

    if load_existing_salt:
        # load existing salt
        salt = load_salt(filename)
    elif save_salt:
        
        # generate new salt and save it
        salt = generate_salt(salt_size)
        with open(f".{filename}.salt", "wb") as salt_file:
            salt_file.write(salt)
    # generate the key from the salt and the password
    derived_key = derive_key(salt, password)
    # encode it using Base 64 and return it
    return base64.urlsafe_b64encode(derived_key)


def encrypt(filename, key):
    """
    Given a filename (str) and key (bytes), it encrypts the file and write it
    """
    fernetkey = Fernet(key)
    with open(filename, "rb") as file:
        # read all file data
        file_data = file.read()
    # encrypt data
    encrypted_data = fernetkey.encrypt(file_data)
    # write the encrypted file
    with open(filename, "wb") as file:
        file.write(encrypted_data)


def decrypt(filename, key):
    """
    Given a filename (str) and key (bytes), it decrypts the file and write it
    """
    fernetkey = Fernet(key)
    with open(filename, "rb") as file:
        # read the encrypted data
        encrypted_data: bytes = file.read()
    # decrypt data
    try:
        decrypted_data: bytes = fernetkey.decrypt(encrypted_data)
    except cryptography.fernet.InvalidToken:
        return 0
    # write the original file
    with open(filename, "wb") as file:
        file.write(decrypted_data)
    return True

def replace_encoding_text(filename, status):
    
    with open(filename, "r+") as file:
        if status == 'encrypted':
            encrypted_data: str = file.read()
            replaced_data: str = encrypted_data.replace('-', '/').translate({"e": "haythereidon'tdoanythinghere123123"})
        elif status == 'decrypted':
            encrypted_data: str = file.read()
            replaced_data: str = encrypted_data.replace('/', '-').translate({"haythereidon'tdoanythinghere123123": "e"})

    with open(filename, "w") as file:
        file.write(replaced_data)

def type_checker():
    ...

def show_note_massege_and_exit():
    print(f"{colorama.Fore.LIGHTWHITE_EX}This process could take some time{colorama.Fore.RESET}")
    print(f"{colorama.Fore.LIGHTYELLOW_EX}PLEASE DON'T DELETE, CREATE OR UPDATE ANY FOLDE OR FILE WHILE THIS PROGRAM IS RUN.{colorama.Fore.RESET}\n")

def show_search_infomation(name, type_, start_path):
    date = datetime.datetime.now()
    sprint(f"\n[{colorama.Fore.LIGHTCYAN_EX}+{colorama.Fore.RESET}] {colorama.Style.BRIGHT}target name: {colorama.Fore.CYAN}{name}{colorama.Fore.RESET}{colorama.Style.RESET_ALL}")
    sprint(f"[{colorama.Fore.LIGHTCYAN_EX}+{colorama.Fore.RESET}] {colorama.Style.BRIGHT}target type: {colorama.Fore.CYAN}{type_}{colorama.Fore.RESET}{colorama.Style.RESET_ALL}")
    sprint(f"[{colorama.Fore.LIGHTCYAN_EX}+{colorama.Fore.RESET}] {colorama.Style.BRIGHT}search from path: {colorama.Fore.CYAN}{start_path}{colorama.Fore.RESET}{colorama.Style.RESET_ALL}")
    sprint(f"[{colorama.Fore.LIGHTCYAN_EX}+{colorama.Fore.RESET}] {colorama.Style.BRIGHT}current date: {colorama.Fore.CYAN}{date:%y.%m.%d %H:%M:%S}{colorama.Fore.RESET}{colorama.Style.RESET_ALL}\n")

def not_around(gpath, home_path) -> list[str]:
    dirs_for_filter: list[str] = []
    files_for_filter: list[str] = []
    try:
        for root, Gdir, Gfiles in os.walk(home_path):
                for i in range(len(Gdir)):
                    if Gdir[i] in [gpath.split('/')[-1]]:

                        gpath: str = root[0:] + '/' + Gdir[i]
                        prossesed_copy_path: str = gpath
                        dirs_for_filter.append(prossesed_copy_path)

                for i in range(len(Gfiles)):
                    if Gfiles[i] in [gpath.split('/')[-1]]:

                        gpath: str = root[0:] + '/' + Gfiles[i]
                        prossesed_copy_path: str = gpath
                        files_for_filter.append(prossesed_copy_path)

        return dirs_for_filter, files_for_filter
    except KeyboardInterrupt:
        sprint(f"\n{colorama.Fore.YELLOW}Good bey !{colorama.Fore.RESET}")
        exit(1)

first_time: int = 1
def filter(arg_path: str = WD, *, is_around: bool =True, skipped: typing.Union[None, list[str]] =None, is_file: bool = False, search_from = '/home'):

    global first_time

    

    path: str = arg_path
    path_: str = path

    input_copy_path: str = path
    

    temp_files: list[str] = []
    temp_dirs: list[str] = []
    repeted_dirs: list[str] = []

    if search_from == None:
        search_from = '/home'
    
    if first_time == 1:

        if is_file:
            show_search_infomation(arg_path, "file", search_from)
        else:
            show_search_infomation(arg_path, "folder", search_from)
        
        show_note_massege_and_exit()

        if not is_around:

            if is_file:
                
                if type(search_from) == str:
                    search_from = '/home'
                    repeted_dirs = not_around(path, search_from)[1]
                    path_ = repeted_dirs
                else:
                    sprint(f"{colorama.Fore.LIGHTRED_EX}start point path shoulde be a string.{colorama.Fore.RESET}")
                    exit(1)
            else:
                if type(search_from) == str:
                    search_from = '/home'
                    repeted_dirs = not_around(path, search_from)[0]
                    path_ = repeted_dirs
                else:
                    sprint(f"{colorama.Fore.LIGHTRED_EX}start point path shoulde be a string.{colorama.Fore.RESET}")
                    exit(1)

        if len(path_) > 1 and type(path_) == list:
            print(f"""{colorama.Fore.GREEN}There a {colorama.Fore.MAGENTA}{len(repeted_dirs)} {colorama.Fore.GREEN}file that have the same name of {colorama.Fore.CYAN}{input_copy_path}{colorama.Fore.GREEN}.{colorama.Fore.RESET}""")
            i: int = 1
            for dir in repeted_dirs:
                if i == 1:
                    print(f"\n    {colorama.Fore.GREEN}{i}. The {colorama.Fore.CYAN}{input_copy_path} {colorama.Fore.GREEN}in [  {colorama.Fore.LIGHTCYAN_EX}{dir} {colorama.Fore.GREEN} ] folder{colorama.Fore.RESET}")
                    i += 1
                    continue
                print(f"    {colorama.Fore.GREEN}{i}. The {colorama.Fore.CYAN}{input_copy_path} {colorama.Fore.GREEN}in [  {colorama.Fore.LIGHTCYAN_EX}{dir}  {colorama.Fore.GREEN}] folder{colorama.Fore.RESET}")
                i += 1
            print(f"    {colorama.Fore.GREEN}{i}. All of them\n")
            try:
                response: int = int(input(f'{colorama.Fore.YELLOW}Choose one of the available options by passing it\'s number: {colorama.Fore.RESET}'))
                response -= 1
            except ValueError or UnboundLocalError:
                sprint(f"\n\n{colorama.Fore.RED}This is not in the valed.{colorama.Fore.RESET}\n")
                exit(1)

            except KeyboardInterrupt:
                sprint(f"\n{colorama.Fore.YELLOW}Good bey !{colorama.Fore.RESET}")
                exit(1)

            if response == len(repeted_dirs):
                sprint(f"\n{colorama.Fore.LIGHTRED_EX}This future is not available yat.{colorama.Fore.RESET}")  #   Make this dream in reality :) 
                exit(1)

            try:
                path_ = repeted_dirs[response]

            except IndexError:
                sprint(f"\n\n{colorama.Fore.RED}This is not in the valed.{colorama.Fore.RESET}\n")
                exit(1)
        else:
            if path_ != [] and type(path_) == list:
                path_ = path_[0]
    if is_file:
        try:
            if os.path.isfile(path_):
                if path_ in ["voldemorts.py", f".{hashlib.md5((input_copy_path+'sdfwlkfiowprgnvEFJVO;HIbvioenyeyvgryw3weqvuincmcoqim').encode()).hexdigest()}salt.salt"]:
                    sprint(f"{colorama.Fore.RED}This file cannot be encrypted/decrypted{colorama.Fore.RESET}")
                    exit(1)
                return path_
        except TypeError:
            sprint(f"{colorama.Fore.RED}There is no file that have this name in your system.{colorama.Fore.RESET}")
            time.sleep(0.4)
            sprint(f"\n{colorama.Fore.YELLOW}Check the path that you insert if you do.{colorama.Fore.RESET}")
            exit(1)
    try:
        for element in os.listdir(path=path_):

            if skipped != None:
                if element in [file_ for file_ in skipped]:  # ["voldemorts.py", "salt.salt", "password.txt"]
                    continue

            if element in ["voldemorts.py", f".{hashlib.md5((input_copy_path+'sdfwlkfiowprgnvEFJVO;HIbvioenyeyvgryw3weqvuincmcoqim').encode()).hexdigest()}salt.salt"]:
                continue
            
            element = os.path.join(path_, element)
                
            if os.path.isfile(element):
                temp_files.append(element)

            if os.path.isdir(element):
                temp_dirs.append(element)
    except TypeError:
        print(f"{colorama.Fore.RED}There is no folder that have this name in your system.{colorama.Fore.RESET}")


    for i in range(len(temp_files)):
        files.append(temp_files[i])

    for i in range(len(temp_dirs)):
        dirs.append(temp_dirs[i])

    if temp_dirs != []:

        for i in range(len(temp_dirs)):
            first_time +=1
            if not is_around:
                filter(os.path.join(path_, temp_dirs[i]))
            else:
                filter(temp_dirs[i])

        return dirs, files

    return temp_dirs, temp_files


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="""File Encryptor Script with a Password""")
    parser.add_argument("folder", help="Folder to encrypt/decrypt")
    parser.add_argument("-Ss", "--salt-size", help="If this is set, a new salt with the passed size is generated, take 16 as default", type=int)
    parser.add_argument("-e", "--encrypt", action="store_true",
                        help="Whether to encrypt the file, only -e or -d can be specified.")
    parser.add_argument("-d", "--decrypt", action="store_true",
                        help="Whether to decrypt the file, only -e or -d can be specified.")
    parser.add_argument("-a", "--is-around", action="store_true", help="If is around, the tool will encrypt/decrypt all the files that is with it in the same folder")
    parser.add_argument("-s", "--skipped", help="If there is any file you want to ignored it", type=list[str])
    parser.add_argument("-f", "--is-file", action="store_true", help="If the path is for a file")
    parser.add_argument("-Sp", "--start-point", help="Determine the starting path of the search, take a path '/home' as default", type=str)

    args = parser.parse_args()
    folder = args.folder

    start_point = args.start_point

    if args.encrypt:

        try:
            password: str = getpass.getpass(f"\n{colorama.Fore.LIGHTCYAN_EX}Enter the password for encryption: {colorama.Fore.RESET}")
        except KeyboardInterrupt:
            sprint(f"\n{colorama.Fore.YELLOW}Good bey !{colorama.Fore.RESET}")
            exit(1)

    elif args.decrypt:

        try:
            password: str = getpass.getpass(f"\n{colorama.Fore.LIGHTCYAN_EX}Enter the password you used for encryption: {colorama.Fore.RESET}")
        except KeyboardInterrupt:
            sprint(f"\n{colorama.Fore.YELLOW}Good bey !{colorama.Fore.RESET}")
            exit(1)

    if args.salt_size:

        if args.decrypt:

            result = input(f"{colorama.Fore.YELLOW}If you set a new salt during the decryption process, this will cause the loss of the old salt that this file was encrypted with, and you will not be able to decrypt it. {colorama.Fore.MAGENTA}Do you want to continue like this{colorama.Fore.MAGENTA}[{colorama.Fore.GREEN}y{colorama.Fore.YELLOW}/{colorama.Fore.RED}N{colorama.Fore.MAGENTA}]{colorama.Fore.WHITE}? {colorama.Fore.RESET}")

            if result.lower() in ['y', 'yes', 'yeah']:
                key: bytes = generate_key(password, salt_size=args.salt_size, save_salt=True, filename=folder)

            else:
                sprint(f"{colorama.Fore.BLUE}Rerun this program again if you want to encrypt anything without this mistake !{colorama.Fore.RESET}")
                exit(0)
        else:
            key: bytes = generate_key(password, salt_size=args.salt_size, save_salt=True)

    else:
        try:
            if args.encrypt:
                try:
                    result_ = input(f"{colorama.Fore.YELLOW}You did not set a salt size, so it well be {colorama.Fore.MAGENTA}16{colorama.Fore.YELLOW} as a default value, {colorama.Fore.CYAN}Did you want to continue {colorama.Fore.MAGENTA}[{colorama.Fore.GREEN}y{colorama.Fore.YELLOW}/{colorama.Fore.RED}N{colorama.Fore.MAGENTA}]{colorama.Fore.WHITE}? {colorama.Fore.RESET}")
                    if result_.lower() in ['y', 'yes', 'yeah']:
                        key: bytes = generate_key(password, salt_size=16, save_salt=True)
                    else:
                        sprint(f"{colorama.Fore.BLUE}Rerun this program again if you want to encrypt anything without this mistake !{colorama.Fore.RESET}")
                        exit(0)
                except KeyboardInterrupt:
                    sprint(f"\n{colorama.Fore.YELLOW}Good bey !{colorama.Fore.RESET}")
                    exit(1)
            else:
                key: bytes = generate_key(password, load_existing_salt=True)
            
        except NameError:
            sprint(f"\n{colorama.Fore.RED}Please specify whether you want to encrypt the file or decrypt it.{colorama.Fore.RESET}")
            exit(1)

    encrypt_ = args.encrypt
    decrypt_ = args.decrypt

    is_file_ = args.is_file

    if encrypt_ and decrypt_:
        print()
        sprint(f"{colorama.Fore.RED}Please specify whether you want to encrypt the file or decrypt it.{colorama.Fore.RESET}")
        exit(1)
    elif encrypt_:
        if args.is_around:
            
            if args.skipped:
                for _file in filter(folder, is_around=True, skipped=args.skipped, is_file=False, search_from=start_point)[1]:
                    encrypt(_file, key)
                    replace_encoding_text(_file, 'encrypted')
            if is_file_:
                _file = filter(folder, is_around=True, skipped=None, is_file=True, search_from=start_point)
                encrypt(_file, key)
                replace_encoding_text(_file, 'encrypted')
            else:
                for _file in filter(folder, is_around=True, skipped=None, is_file=False, search_from=start_point)[1]:
                    encrypt(_file, key)
                    replace_encoding_text(_file, 'encrypted')

        elif args.skipped:
            for _file in filter(folder, is_around=False, skipped=args.skipped, is_file=False, search_from=start_point)[1]:
                    encrypt(_file, key)
                    replace_encoding_text(_file, 'encrypted')
        else:
            if is_file_:
                _file = filter(folder, is_around=False, skipped=None, is_file=True, search_from=start_point)
                encrypt(_file, key)
                replace_encoding_text(_file, 'encrypted')
            else:
                for _file in filter(folder, is_around=False, skipped=None, is_file=False, search_from=start_point)[1]:
                        encrypt(_file, key)
                        replace_encoding_text(_file, 'encrypted')

        sprint(f"{colorama.Fore.LIGHTGREEN_EX}File Encrypted successfully{colorama.Fore.RESET}")

    elif decrypt_:
        if args.is_around:
            
            if args.skipped:
                            for _file in filter(folder, is_around=True, skipped=args.skipped, is_file=False, search_from=start_point)[1]:
                                replace_encoding_text(_file, 'decrypted')
                                if decrypt(_file, key):
                                    print(f"{colorama.Fore.LIGHTGREEN_EX}[{_file.split('/')[-1]}] decrypted successfully{colorama.Fore.RESET}")
                                else:
                                    sprint(f"{colorama.Fore.RED}Invalid token, most likely the password is incorrect{colorama.Fore.RESET}")
                                    exit(1)
            if is_file_:
                _file = filter(folder, is_around=True, skipped=None, is_file=True, search_from=start_point)
                replace_encoding_text(_file, 'decrypted')
                if decrypt(_file, key):
                    sprint(f"{colorama.Fore.LIGHTGREEN_EX}[{_file.split('/')[-1]}] decrypted successfully{colorama.Fore.RESET}")
                else:
                    sprint(f"{colorama.Fore.RED}Invalid token, most likely the password is incorrect{colorama.Fore.RESET}")
                    exit(1)
            else:
                for _file in filter(folder, is_around=True, skipped=None, is_file=False, search_from=start_point)[1]:
                        replace_encoding_text(_file, 'decrypted')
                        if decrypt(_file, key):
                            print(f"{colorama.Fore.LIGHTGREEN_EX}[{_file.split('/')[-1]}] decrypted successfully{colorama.Fore.RESET}")
                        else:
                            sprint(f"{colorama.Fore.RED}Invalid token, most likely the password is incorrect{colorama.Fore.RESET}")
                            exit(1)
                    
        elif args.skipped:
            for _file in filter(folder, is_around=False, skipped=args.skipped, is_file=False, search_from=start_point)[1]:
                    replace_encoding_text(_file, 'decrypted')
                    if decrypt(_file, key):
                        print(f"{colorama.Fore.LIGHTGREEN_EX}[{_file.split('/')[-1]}] decrypted successfully{colorama.Fore.RESET}")
                    else:
                        sprint(f"{colorama.Fore.RED}Invalid token, most likely the password is incorrect{colorama.Fore.RESET}")
                        exit(1)
        else:
            if is_file_:
                _file = filter(folder, is_around=False, skipped=None, is_file=True, search_from=start_point)
                replace_encoding_text(_file, 'decrypted')
                if decrypt(_file, key):
                    print(f"{colorama.Fore.LIGHTGREEN_EX}[{_file.split('/')[-1]}] decrypted successfully{colorama.Fore.RESET}")
                else:
                    sprint(f"{colorama.Fore.RED}Invalid token, most likely the password is incorrect{colorama.Fore.RESET}")
                    exit(1)
            else:
                for _file in filter(folder, is_around=False, skipped=None, is_file=False, search_from=start_point)[1]:
                        replace_encoding_text(_file, 'decrypted')
                        if decrypt(_file, key):
                            print(f"{colorama.Fore.LIGHTGREEN_EX}[{_file.split('/')[-1]}] decrypted successfully{colorama.Fore.RESET}")
                        else:
                            sprint(f"{colorama.Fore.RED}Invalid token, most likely the password is incorrect{colorama.Fore.RESET}")
                            exit(1)
    else:
         sprint(f"{colorama.Fore.RED}Please specify whether you want to encrypt the file or decrypt it.{colorama.Fore.RESET}")
         exit(1)

    # password = 'moh'

    # key = generate_key(password, salt_size=128, save_salt=True)

    # for _file in filter('people info', is_around=False, skipped=None)[1]:
    #         encrypt(_file, key)

    # print("File Encrypted successfully")