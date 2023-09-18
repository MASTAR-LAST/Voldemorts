#!/usr/bin/env python3

# NOTE: https://docs.python.org/3/library/argparse.html#argument-groups
# Copyright (c) 2023 Muhammed Alkohawaldeh
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from random import sample

from rich.progress import track
from subprocess import check_output, run
from typing import Union, LiteralString, Literal, List

from fake_useragent import UserAgent
from requests import get, Response
from bs4 import BeautifulSoup

import os
import platform
import hashlib
import secrets
import base64
import getpass
import colorama
import datetime
import time
import sys


__version__: str = "1.1.0"
__status__: str = "stable" # NOTE: stable, beta, alpha for more information see <https://en.wikipedia.org/wiki/Software_release_life_cycle>

ua = {"User-Agent": UserAgent().random}

def version_checker() -> None:
    """Search for a new release in github repo.
    """
    current_version: list[LiteralString] = __version__.split('.')
    sprint(f"\n{colorama.Fore.YELLOW}Checke for updates...{colorama.Fore.RESET}\n")
    respone: Response = get("https://github.com/MASTAR-LAST/Voldemorts/tags", headers=ua)
    if respone.status_code != 200:
        sprint(f"{colorama.Fore.RESET}Problem with internet..!\n{colorama.Fore.RESET}")
        return # NOTE: Arely return to stop the function
    soup: BeautifulSoup = BeautifulSoup(respone.text, 'html.parser')
    for link in soup.find_all("a", attrs={"class": "Link--primary Link"}).pop(0):
        full_version: str = str(link).split(">")[0]
        version_number: list[str] = full_version.removeprefix('v').split('-')[0].split('.')
        tracker: int = 0
        for i in range(len(version_number)):
            if int(version_number[i]) > int(current_version[i]):
                sprint(f"{colorama.Fore.GREEN}New update was found !\n{colorama.Fore.RESET}")
                try:
                    user_respone: str = input(f"{colorama.Fore.GREEN}Version {colorama.Fore.CYAN}{colorama.Style.BRIGHT}{full_version}{colorama.Style.RESET_ALL}{colorama.Fore.GREEN} is available, {colorama.Fore.YELLOW}Do want to install it{colorama.Fore.RESET} [{colorama.Fore.GREEN}Y{colorama.Fore.RESET}/{colorama.Fore.RED}n{colorama.Fore.RESET}]{colorama.Fore.BLUE}?{colorama.Fore.RESET} ")
                except KeyboardInterrupt:
                    sprint(f"{colorama.Fore.YELLOW}Good Bye!{colorama.Fore.RESET}")
                    exit(0)

                if user_respone.strip().lower() in ['y', 'yes', 'yeah', '1']:
                    sprint(f"{colorama.Fore.GREEN}Start installtion...{colorama.Fore.RESET}")
                    tool_updater(soup)

                elif user_respone.strip().lower() in ['n', 'no', 'nuh', '0', 'nop']:
                    sprint(f"\r\n{colorama.Fore.YELLOW}Checker Finished{colorama.Fore.RESET}")
                
                else:
                    sprint(f"{colorama.Fore.RED}This answer is not valide{colorama.Fore.RESET},{colorama.Fore.YELLOW}Update automatically start...{colorama.Fore.RESET}\n")
                    tool_updater(soup)
            else:
                tracker += 1

            if tracker == 3:
                sprint(f"{colorama.Fore.GREEN}Your tool is up to date{colorama.Fore.RESET}\n")

def get_user_mode() -> str:
    """Get the user permissions

    Returns:
        str: return a string that contane colored text, `Root` if it's a root or run the file with sudo and `Regular User` if none of the prives is true
    """

    mode: str = getpass.getuser()
    UID: int = os.geteuid()

    if mode.lower().strip() == 'root' or UID == 0:
        return f"{colorama.Fore.GREEN}{colorama.Style.BRIGHT}Root{colorama.Style.RESET_ALL}{colorama.Fore.RESET}"
    else:
        return f"{colorama.Fore.BLUE}{colorama.Style.BRIGHT}Regular User{colorama.Style.RESET_ALL}{colorama.Fore.RESET}"

def downloade_link_founder(page: BeautifulSoup) -> str:
    """generate the downloade link for a `.zip` file of the release.

    Args:
        page (BeautifulSoup): Github page to scarpe it and get the link.

    Returns:
        str: return the downloade link
    """
    URL_BASE: Literal['https://github.com'] = "https://github.com"
    url_element = page.find_all("a", attrs={"class": "Link--muted", "rel": "nofollow"}).pop(0)
    url: str = URL_BASE + str(url_element).split(">")[0].split()[2].split("=")[-1].split("\"")[1]
    return url


def tool_updater(page: BeautifulSoup) -> None:
    """Run a bash script to rebuild the tool after the update. 

    Args:
        page (BeautifulSoup): Github page to scarpe it and get the link.
    """
    link: str = downloade_link_founder(page)
    dir_name: str = "Voldemorts-" + link.split("/")[-1].removeprefix("v").removesuffix(".zip")

    update_status: int = run(f"./tool_updater25T.sh {link} {dir_name}", shell=True).returncode
    if update_status == 1:
        sprint(f"{colorama.Fore.RED}Unable to update the tool{colorama.Fore.RESET}, {colorama.Fore.YELLOW}Please roport at https://github.com/MASTAR-LAST/Voldemorts/issues{colorama.Fore.RESET}")


def sprint(text: str, second: int = 0.03, end: str = '\n') -> None:
    """Print the text slowly.

    Args:
        text (str): the staring that want to print it to the termenal.
        second (float, optional): the time between each char. Defaults to 0.03.
        end (str, optional): char to write in the end or line. Defaults to '\n'.
    """
    for line in text + end:
        sys.stdout.write(line)
        sys.stdout.flush()
        time.sleep(second)

files: list[str] = []
dirs: list[str] = []

OS_NAME: str = platform.system()
WD: str = os.getcwd()

def report_writer(
        succeeded_files: Union[list[str], None] = None, 
        failed_file:Union[str, None] = None, 
        platform: str = OS_NAME, 
        main: str = WD, 
        algorithm_type: Union[str, None] = None,
        algorithm_status: Union[str, None] = None,
        error_message: Union[str, None] = None,
        key: Union[str, None] = None
        ) -> tuple[bool, str]:
    """Write a report about the error in a file and make it in the dir that is run the tool from.

    Args:
        succeeded_files (Union[list[str], None], optional): _description_. Defaults to None.
        failed_file (Union[str, None], optional): _description_. Defaults to None.
        platform (str, optional): Operating System name. Defaults to OS_NAME.
        main (str, optional): your current working directory. Defaults to WD.
        algorithm_type (Union[str, None], optional): what is the algorithm that raise this error. Defaults to None.
        algorithm_status (Union[str, None], optional): when the error happend while `Encryption` or `Decryption`. Defaults to None.
        error_message (Union[str, None], optional): the full error message for the error. Defaults to None.
        key (Union[str, None], optional): the Globale Encryption Key for the file, print just if the `algorithm_status` is `Decryption` only. Defaults to None.

    Returns:
        tuple[bool, str]: return the `True` if the report was written successfully with the `report path` else  return `False` and `Error` string.
    """
    try: 
        report_file_name: str = f"{WD}/{algorithm_status}_{algorithm_type}_report.txt"
        with open(f"{report_file_name}", "w") as report_file:

            report_body: str = f"""Report:
        General:
            Platform: {platform}
            Main Path: {main}
            Time: {datetime.datetime.now(): "%Y/%m/%d, %H:%M:%S"}
        
        Error Information:
            Failed: {failed_file} 
            Success: {succeeded_files}
            Encryption Algorithm: {algorithm_type}
            Encryption Algorithm Status: {algorithm_status}

            Error message:
            --------Error Message Start--------
                {error_message}
            --------Error Message End--------

        Reporting Resources:
            Github: https://github.com/MASTAR-LAST/Voldemorts/issues
            
            Contacts Me:
                Email: twisters50team@gmail.com
                X: twisters50
                
Note: Please open a new issue in GitHub and attach with your report how it happened and where in detail
                    """
            if algorithm_status == 'Decryption':
                # NOTE: Print the encryption key with the report
                report_body: str = f"""Report:
        General:
            Platform: {platform}
            Main Path: {main}
            Time: {datetime.datetime.now(): "%Y/%m/%d, %H:%M:%S"}
        
        Error Information:
            Failed: {failed_file} 
            Success: {succeeded_files}
            Encryption Algorithm: {algorithm_type}
            Encryption Algorithm Status: {algorithm_status}

            Error message:
            --------Error Message Start--------
                {error_message}
            --------Error Message End--------
            
        Secret Data:
            Encryption Key: [{key}], Note: the encryption key is all the text between [] and not [] themselves

        Reporting Resources:
            Github: https://github.com/MASTAR-LAST/Voldemorts/issues
            
            Contacts Me:
                Email: twisters50team@gmail.com
                X: twisters50

Note: Please open a new issue in GitHub and attach with your report how it happened and where in detail
                    """
            report_file.write(report_body)

            return (True, f"{report_file_name}")
        
    except Exception as error:
        sprint(f"{colorama.Fore.RED}Unable to write the report, please try again in with sudo command.{colorama.Fore.RESET}")
        sprint(f"{colorama.Fore.YELLOW}If nothing works please report at the link in messages.{colorama.Fore.RESET}")

        return (False, "Error")
        

def second_layer_encryption(password: str, filename: str) -> Union[None, str]:
    """Encrypt the file with AES encryption algorithm

    Args:
        password (str): the Global Encryption Key to encrypt the file with it 
        filename (str): file path

    Returns:
        Union[None, str]: return `None` if there is an error and return `string` if everything is OK
    """
    encrypted_files: list[str] = []
    filename = filename[1]
    for filename_ in filename:
        try:
                salt = b'\x15\x0b_\xfd\x84"P\x8cp3r\xceY\xc2I\x07'

                key = PBKDF2(password, salt, dkLen=16)

                with open(filename_, "rb") as file:
                    file_data = file.read()

                    cipher = AES.new(key, AES.MODE_CBC)
                    ciphered_data = cipher.encrypt(pad(file_data, AES.block_size))

                with open(filename_, 'wb') as _file:
                    _file.write(salt + cipher.iv + ciphered_data)
                    encrypted_files.append(filename_)
        except Exception as error:
            sprint(f"{colorama.Fore.RED}Something goes wrong while encrypting the file `{filename_}` with AES algorithm.{colorama.Fore.RESET}", second=0.02)
            sprint(f"{colorama.Fore.RED}Please report at https://github.com/MASTAR-LAST/Voldemorts/issues about this problem.{colorama.Fore.RESET}", second=0.02)
            sprint(f"{colorama.Fore.YELLOW}Encryption process will stop at this point, We will write a report for this error.{colorama.Fore.RESET}", second=0.01)
            Ok, report_path = report_writer(succeeded_files=encrypted_files, 
                                            failed_file=filename_, 
                                            algorithm_type='AES', 
                                            algorithm_status='Encryption', 
                                            error_message=error)
            if Ok:
                sprint(f"{colorama.Fore.YELLOW}Your report is ready in [{report_path}].{colorama.Fore.RESET}", second=0.01)
                sprint(f"{colorama.Fore.YELLOW}The layers of encryption that have been set will be {colorama.Fore.GREEN}reversed before completion{colorama.Fore.YELLOW}, {colorama.Style.BRIGHT}Do not close the program or YOU WILL LOSE YOUR DATA{colorama.Style.RESET_ALL}.{colorama.Fore.RESET}", second=0.01)

            return "reverse"


def second_layer_decryption(password: str, filename: str) -> None:
    """Decrypt the file with AES encryption algorithm

    Args:
        password (str): the Global Encryption Key to decrypt the file with it 
        filename (str): file path
    """
    decrypted_files: list[str] = []
    filename = filename[1]
    try:
        for filename_ in filename:
            with open(filename_, 'rb') as encryptfile:
                file_data = encryptfile.read()

                salt = file_data[:16]
                iv = file_data[16:32]
                decrypt_data = file_data[32:]

                key = PBKDF2(password, salt, dkLen=16)

                cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                original_data = unpad(cipher.decrypt(decrypt_data), AES.block_size)

            with open(filename_, 'wb') as _encryptfile:
                _encryptfile.write(original_data)
                decrypted_files.append(filename_)
    except Exception as error:
            sprint(f"{colorama.Fore.RED}Something goes wrong while decrypting the file `{filename_}` from AES algorithm.{colorama.Fore.RESET}", second=0.02)
            sprint(f"{colorama.Fore.RED}Please report at https://github.com/MASTAR-LAST/Voldemorts/issues about this problem.{colorama.Fore.RESET}", second=0.02)
            sprint(f"{colorama.Fore.YELLOW}Decryption process will stop at this point, We will write a report for this error.{colorama.Fore.RESET}", second=0.01)
            Ok, report_path = report_writer(succeeded_files=decrypted_files,
                                            failed_file=filename_, 
                                            algorithm_type='AES', 
                                            algorithm_status='Decryption', 
                                            error_message=error,
                                            key=key)
            if Ok:
                sprint(f"{colorama.Fore.YELLOW}Your report is ready in [{report_path}].{colorama.Fore.RESET}", second=0.01)
            exit(1)

def generate_salt(size: int = 16) -> bytes:
    """Generate the salt used for key derivation,`size` is the length of the salt to generate

    Args:
        size (int, optional): salte size. Defaults to 16.

    Returns:
        bytes: return the salte as a bytes
    """
    return secrets.token_bytes(size)


def derive_key(salt: bytes, password: str) -> bytes: # NOTE: Global Encryption Key AKA GEK.
    """Derive the key from the `password` using the passed `salt`

    Args:
        salt (bytes): the salt to make a `Global Encryption Key` with it.
        password (str): the password to make the `GEK` also.

    Returns:
        bytes: return the mix of password and salt
    """
    kdf: Scrypt = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())


def load_salt(filename) -> bytes:
    # load salt from `hash_file_name`.salt file
    return open(f".{filename}.salt", "rb").read()


def generate_key(password: str, salt_size: int = 16, load_existing_salt: bool = False, save_salt: bool = True, filename: str = 'ex') -> bytes:
    """Generates a key from a `password` and the salt, If `load_existing_salt` is True, it'll load the salt from a file
    in the current directory called "salt.salt", If `save_salt` is True, then it will generate a new salt and save it to "salt.salt"

    Args:
        password (str): The password the to make `GEK` with
        salt_size (int, optional): the salt size to make `GEK`. Defaults to 16.
        load_existing_salt (bool, optional): If there is a file that have the past salt. Defaults to False.
        save_salt (bool, optional): _description_. Defaults to True.
        filename (str, optional): the salt file name. Defaults to 'ex'.

    Returns:
        bytes: return the Global Encryption Key aka GEK
    """
    filename: str = hashlib.md5((filename+'sdfwlkfiowprgnvEFJVO;HIbvioenyeyvgryw3weqvuincmcoqim').encode()).hexdigest()

    if load_existing_salt:
        # load existing salt
        salt: bytes = load_salt(filename)
    elif save_salt:
        
        # generate new salt and save it
        salt: bytes = generate_salt(salt_size)
        with open(f".{filename}.salt", "wb") as salt_file:
            salt_file.write(salt)
    # generate the key from the salt and the password
    derived_key: bytes = derive_key(salt, password)
    # encode it using Base 64 and return it
    return base64.urlsafe_b64encode(derived_key)


def encrypt(filename: tuple[list, list[str]], key: bytes) -> Union[None, str]:
    """Given a filename (str) and key (bytes), it encrypts the file and write it

    Args:
        filename (tuple[list, list[str]]): the files path list 
        key (bytes): Global Encryption Key

    Returns:
        Union[None, str]: return `None` if there is an error and return `string` if everything is OK
    """
    try:
        encrypted_files: list[str] = []
        filename = filename[1]
        if type(filename) != str:
            for filename_ in filename:
                fernetkey = Fernet(key)
                with open(filename_, "rb") as file:
                    # read all file data
                    file_data = file.read()
                # encrypt data
                encrypted_data = fernetkey.encrypt(file_data)
                # write the encrypted file
                with open(filename_, "wb") as file:
                    file.write(encrypted_data)
        else:
            for filename_ in filename:
                    fernetkey = Fernet(key)
                    with open(filename_, "rb") as file:
                        # read all file data
                        file_data = file.read()
                    # encrypt data
                    encrypted_data = fernetkey.encrypt(file_data)
                    # write the encrypted file
                    with open(filename_, "wb") as file:
                        file.write(encrypted_data)
                        encrypted_files.append(filename_)
    except Exception as error:
            sprint(f"{colorama.Fore.RED}Something goes wrong while encrypting the file `{filename_}` with Fernet algorithm.{colorama.Fore.RESET}", second=0.02)
            sprint(f"{colorama.Fore.RED}Please report at https://github.com/MASTAR-LAST/Voldemorts/issues about this problem.{colorama.Fore.RESET}", second=0.02)
            sprint(f"{colorama.Fore.YELLOW}Encryption process will stop at this point, We will write a report for this error.{colorama.Fore.RESET}", second=0.01)
            Ok, report_path = report_writer(succeeded_files=encrypted_files,
                                            failed_file=filename_, 
                                            algorithm_type='Fernet', 
                                            algorithm_status='Encryption', 
                                            error_message=error)
            if Ok:
                sprint(f"{colorama.Fore.YELLOW}Your report is ready in [{report_path}].{colorama.Fore.RESET}", second=0.01)
                sprint(f"{colorama.Fore.YELLOW}The layers of encryption that have been set will be {colorama.Fore.GREEN}reversed before completion{colorama.Fore.YELLOW}, {colorama.Style.BRIGHT}Do not close the program or YOU WILL LOSE YOUR DATA{colorama.Style.RESET_ALL}.{colorama.Fore.RESET}", second=0.01)

            return "reverse"


def decrypt(filename: tuple[list, list[str]], key: bytes) -> Union[Union[int, bool], str]:
    """Given a filename (str) and key (bytes), it decrypts the file and write it

    Args:
        filename (tuple[list, list[str]]): the files path list 
        key (bytes): Global Encryption Key

    Returns:
        Union[None, str]: return `None` if there is an error and return `string` if everything is OK
    """
    try:
        decrypted_files: list[str] = []
        filename = filename[1]
        for filename_ in filename:
            fernetkey = Fernet(key)
            with open(filename_, "rb") as file:
                # read the encrypted data
                encrypted_data: bytes = file.read()
            # decrypt data
            try:
                decrypted_data: bytes = fernetkey.decrypt(encrypted_data)
            except cryptography.fernet.InvalidToken:
                return 0
            # write the original file
            with open(filename_, "wb") as file:
                file.write(decrypted_data)
            return True
    
    except Exception as error:
            sprint(f"{colorama.Fore.RED}Something goes wrong while decrypting the file `{filename_}` from AES algorithm.{colorama.Fore.RESET}", second=0.02)
            sprint(f"{colorama.Fore.RED}Please report at https://github.com/MASTAR-LAST/Voldemorts/issues about this problem.{colorama.Fore.RESET}", second=0.02)
            sprint(f"{colorama.Fore.YELLOW}Decryption process will stop at this point, We will write a report for this error.{colorama.Fore.RESET}", second=0.01)
            Ok, report_path = report_writer(succeeded_files=decrypted_files,
                                            failed_file=filename_, 
                                            algorithm_type='AES', 
                                            algorithm_status='Decryption', 
                                            error_message=error,
                                            key=key)
            if Ok:
                sprint(f"{colorama.Fore.YELLOW}Your report is ready in [{report_path}].{colorama.Fore.RESET}", second=0.01)
            exit(1)

def replace_encoding_text(filename: tuple[list, list[str]], status: str) -> Union[None, str]:
        """replaceing the chars with other chars as an another encryption layer. 

        Args:
            filename (tuple[list, list[str]]): the files path list.
            status (str): what is the `algorithm status`.

        Returns:
            Union[None, str]: return `None` if there is an error and return `string` if everything is OK
        """
        encrypted_files: list[str] = []
        try:
            filename = filename[1]
            for filename_ in filename:
                with open(filename_, "r+") as file:
                    if status == 'encrypted':
                        encrypted_data: str = file.read()
                        replaced_data: str = encrypted_data.replace('-', '/').translate({"e": "haythereidon'tdoanythinghere123123"})
                    elif status == 'decrypted':
                        encrypted_data: str = file.read()
                        replaced_data: str = encrypted_data.replace('/', '-').translate({"haythereidon'tdoanythinghere123123": "e"})

                with open(filename_, "w") as file:
                    file.write(replaced_data)
                    encrypted_files.append(filename_)
        except Exception as error:
                sprint(f"{colorama.Fore.RED}Something goes wrong while encryption/decryption the file `{filename_}` with Replacing Chars algorithm.{colorama.Fore.RESET}", second=0.02)
                sprint(f"{colorama.Fore.RED}Please report at https://github.com/MASTAR-LAST/Voldemorts/issues about this problem.{colorama.Fore.RESET}", second=0.02)
                sprint(f"{colorama.Fore.YELLOW}Encryption/Decryption process will stop at this point, We will write a report for this error.{colorama.Fore.RESET}", second=0.01)
                Ok, report_path = report_writer(succeeded_files=encrypted_files,
                                                failed_file=filename_, 
                                                algorithm_type='Replacing Chars', 
                                                algorithm_status='Encryption/Decryption', 
                                                error_message=error)
                if Ok:
                    sprint(f"{colorama.Fore.YELLOW}Your report is ready in [{report_path}].{colorama.Fore.RESET}", second=0.01)
                    sprint(f"{colorama.Fore.YELLOW}The layers of encryption that have been set will be {colorama.Fore.GREEN}reversed before completion{colorama.Fore.YELLOW}, {colorama.Style.BRIGHT}Do not close the program or YOU WILL LOSE YOUR DATA{colorama.Style.RESET_ALL}.{colorama.Fore.RESET}", second=0.01)

                return "reverse"


def show_note_massege_and_exit() -> None:
    """print a warnang messages and exit.
    """
    print(f"{colorama.Fore.LIGHTWHITE_EX}This process could take some time{colorama.Fore.RESET}")
    print(f"{colorama.Fore.LIGHTYELLOW_EX}PLEASE DON'T DELETE, CREATE OR UPDATE ANY FOLDE OR FILE WHILE THIS PROGRAM IS RUN.{colorama.Fore.RESET}\n")

def show_search_infomation(name: str, type_: str, start_path: str) -> None:
    """print general information about the encryption prossece.

    Args:
        name (str): file name.
        type_ (str): file type, `folder` or `file`.
        start_path (str): the path that the tool will start searching from it.
    """
    date: datetime.datetime = datetime.datetime.now()
    sprint(f"\n[{colorama.Fore.LIGHTCYAN_EX}+{colorama.Fore.RESET}] {colorama.Style.BRIGHT}target name: {colorama.Fore.CYAN}{name}{colorama.Fore.RESET}{colorama.Style.RESET_ALL}")
    sprint(f"[{colorama.Fore.LIGHTCYAN_EX}+{colorama.Fore.RESET}] {colorama.Style.BRIGHT}target type: {colorama.Fore.CYAN}{type_}{colorama.Fore.RESET}{colorama.Style.RESET_ALL}")
    sprint(f"[{colorama.Fore.LIGHTCYAN_EX}+{colorama.Fore.RESET}] {colorama.Style.BRIGHT}search from path: {colorama.Fore.CYAN}{start_path}{colorama.Fore.RESET}{colorama.Style.RESET_ALL}")
    sprint(f"[{colorama.Fore.LIGHTCYAN_EX}+{colorama.Fore.RESET}] {colorama.Style.BRIGHT}current date: {colorama.Fore.CYAN}{date:%y.%m.%d %H:%M:%S}{colorama.Fore.RESET}{colorama.Style.RESET_ALL}\n")

def not_around(gpath: str, home_path: str) -> list[str]:
    """Walk throwe the folders the finale file.

    Args:
        gpath (str): the name of the `file/folde` that the tool searching for.
        home_path (str): the path that the tool will start searching from it.

    Returns:
        list[str]: return a list contane the file/folder paths.
    """
    dirs_for_filter: list[str] = []
    files_for_filter: list[str] = []
    try:
        for root, Gdir, Gfiles in track(os.walk(home_path), "Searching...", show_speed=False, update_period=0.01):
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
        print()

        return dirs_for_filter, files_for_filter
    except KeyboardInterrupt:
        sprint(f"\n{colorama.Fore.YELLOW}Good bey !{colorama.Fore.RESET}")
        exit(1)

def ask_for_file_path(repeted_dirs: list[str], input_copy_path: str) -> int:
            """Print the possible file/folder paths if there is more than one of them.

            Args:
                repeted_dirs (list[str]): the list of the possible paths.
                input_copy_path (str): the file/folder name.

            Returns:
                int: return the index of the element in the path array, or return the length of arrary which means that you want to encrypt/decrypt all of them.
            """
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
                response: int = int(input(f'{colorama.Fore.YELLOW}Choose one of the available options by passing it\'s number: {colorama.Fore.RESET}').strip())
                response -= 1
            except ValueError or UnboundLocalError:
                sprint(f"\n\n{colorama.Fore.RED}This is not in the valed.{colorama.Fore.RESET}\n")
                exit(1)

            except KeyboardInterrupt:
                sprint(f"\n{colorama.Fore.YELLOW}Good bey !{colorama.Fore.RESET}")
                exit(1)

            return response

first_time: int = 1
all_dirs: bool = False

def filter(arg_path: str = WD, *, is_around: bool = True, skipped: Union[None, list[str]] = None, is_file: bool = False, search_from = '/home'):
    """Filter the search results

    Args:
        arg_path (str, optional): File/Folder name that you want to search for. Defaults to WD.
        is_around (bool, optional): If the file is around the script "in the same folder". Defaults to True.
        skipped (Union[None, list[str]], optional): What is the files/folders name that you want to skip them. Defaults to None.
        is_file (bool, optional): If the file that you want to encrypt/decrypt is a file not folder. Defaults to False.
        search_from (str, optional): What is the dir that you want to start searching from. Defaults to '/home'.

    Returns:
        _type_: _description_
    """ # TODO: need a more details

    global first_time, all_dirs

    
    path: str = arg_path
    path_: Union[str, list[str]] = path

    input_copy_path: str = path
    

    temp_files: list[str] = []
    temp_dirs: list[str] = []
    repeted_dirs: list[str] = []

    if search_from == None and not is_around:
        search_from = '/home'

    if search_from == None and is_around:
        search_from = check_output('pwd').decode('utf-8').strip().replace("\\", " ")
    
    if first_time == 1:

        if is_file:
            show_search_infomation(arg_path, "file", search_from)
        else:
            show_search_infomation(arg_path, "folder", search_from)
        
        show_note_massege_and_exit()

        if not is_around:

            if is_file:
                
                if type(search_from) == str:
                    search_from = f'{search_from}'
                    repeted_dirs = not_around(path, search_from)[1]
                    path_ = repeted_dirs
                else:
                    sprint(f"{colorama.Fore.LIGHTRED_EX}start point path shoulde be a string.{colorama.Fore.RESET}")
                    exit(1)
            else:
                if type(search_from) == str:
                    search_from = f'{search_from}'
                    repeted_dirs = not_around(path, search_from)[0]
                    path_ = repeted_dirs
                else:
                    sprint(f"{colorama.Fore.LIGHTRED_EX}start point path shoulde be a string.{colorama.Fore.RESET}")
                    exit(1)

        if len(path_) > 1 and type(path_) == list:

            response: int = ask_for_file_path(repeted_dirs, input_copy_path)

            if response == len(repeted_dirs):
                # return_formater_list = [[]]
                # return return_formater_list
                # sprint(f"\n{colorama.Fore.LIGHTRED_EX}This future is not available yat.{colorama.Fore.RESET}")
                # exit(1)
                temp_dirs_list_for_all_dirs_opt: list[str] = repeted_dirs
                all_dirs = True

            try:
                if not all_dirs:
                    path_ = repeted_dirs[response]

            except IndexError:
                sprint(f"\n\n{colorama.Fore.RED}This is not in the valed.{colorama.Fore.RESET}\n")
                exit(1)
        else:
            if path_ != [] and type(path_) == list:
                path_ = path_[0]
    if is_file:
        try:
            if not all_dirs:
                if os.path.isfile(path_):
                    if path_ in ["voldemorts.py", f".{hashlib.md5((input_copy_path+'sdfwlkfiowprgnvEFJVO;HIbvioenyeyvgryw3weqvuincmcoqim').encode()).hexdigest()}.salt"]:
                        sprint(f"{colorama.Fore.RED}This file cannot be encrypted/decrypted{colorama.Fore.RESET}")
                        exit(1)
                    return ([], [path_])
            if all_dirs:
                files_temp_list: list[str] = []
                for each_file in temp_dirs_list_for_all_dirs_opt:

                    if os.path.isfile(each_file):
                        if skipped != None:
                            if each_file in [file_ for file_ in skipped]:  # NOTE:  تحتاج إلى اسم المسار كاملا لكي تتجاهل الملف 
                                continue

                        if each_file in ["voldemorts.py", f".{hashlib.md5((input_copy_path+'sdfwlkfiowprgnvEFJVO;HIbvioenyeyvgryw3weqvuincmcoqim').encode()).hexdigest()}.salt"]:
                            sprint(f"{colorama.Fore.RED}`{each_file.split('/')[-1]}` file cannot be encrypted/decrypted{colorama.Fore.RESET}")
                            continue
                        files_temp_list.append(each_file)
                return ([], files_temp_list)  # NOTE: EARLY RETURN
        except TypeError:
            sprint(f"{colorama.Fore.RED}There is no file that have this name in your system.{colorama.Fore.RESET}")
            time.sleep(0.4)
            sprint(f"\n{colorama.Fore.YELLOW}Check the path that you insert if you do.{colorama.Fore.RESET}")
            exit(1)
    try:
        if not all_dirs and not is_file:
            for element in os.listdir(path=path_):

                if skipped != None:
                    if element in [file_ for file_ in skipped]:  # HACK: ["voldemorts.py", "`file_name_hash`.salt", "password.txt"]
                        continue

                if element in ["voldemorts.py", f".{hashlib.md5((input_copy_path+'sdfwlkfiowprgnvEFJVO;HIbvioenyeyvgryw3weqvuincmcoqim').encode()).hexdigest()}.salt"]:
                    continue
                
                element = os.path.join(path_, element)
                    
                if os.path.isfile(element):
                    temp_files.append(element)

                if os.path.isdir(element):
                    temp_dirs.append(element)

        if all_dirs:
            for eche_dir in all_dirs:
                for element in os.listdir(path=eche_dir):

                    if skipped != None:
                        if element in [file_ for file_ in skipped]:  # HACK: ["voldemorts.py", "`file_name_hash`.salt", "password.txt"]
                            continue

                    if element in ["voldemorts.py", f".{hashlib.md5((input_copy_path+'sdfwlkfiowprgnvEFJVO;HIbvioenyeyvgryw3weqvuincmcoqim').encode()).hexdigest()}.salt"]:
                        continue
                    
                    element = os.path.join(path_, element)
                        
                    if os.path.isfile(element):
                        temp_files.append(element)

                    if os.path.isdir(element):
                        temp_dirs.append(element)
    except TypeError:
        print(f"{colorama.Fore.RED}There is no folder that have this name in your system.{colorama.Fore.RESET}")
        exit(1)

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
#  NOTE: reversing technique 
def reveres_encryption(file_path: str, key: bytes, reverse_algorithm: Union[None, str]) -> None:
    """Reveresing the encryption algorithms if one of them is faile.

    Args:
        file_path (str): the file that failes.
        key (bytes): Globle Encryption Key.
        reverse_algorithm (Union[None, str]): the algorithm that faile.
    """
    if reverse_algorithm.lower().strip() == 'aes':
        replace_encoding_text(file_path, "decrypted")
        decrypt(file_path, key)
        exit(1)
    elif reverse_algorithm.lower().strip() == 'fernet':
        exit(1)
    elif reverse_algorithm.lower().strip() == 'replacing':
        decrypt(file_path, key)
        exit(1)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="""File Encrypting Script with a Password""")

    parser.add_argument("folder", help="Folder to encrypt/decrypt", nargs='?')
    parser.add_argument("-Ss", "--salt-size", help="If this is set, a new salt with the passed size is generated, take 16 as default", type=int)
    parser.add_argument("-e", "--encrypt", action="store_true", help="Whether to encrypt the file, only -e or -d can be specified.")
    parser.add_argument("-d", "--decrypt", action="store_true", help="Whether to decrypt the file, only -e or -d can be specified.")
    parser.add_argument("-a", "--is-around", action="store_true", help="If is around, the tool will encrypt/decrypt all the files that is with it in the same folder")
    parser.add_argument("-s", "--skipped", help="If there is any file you want to ignored it", nargs='*', type=list[str])
    parser.add_argument("-f", "--is-file", action="store_true", help="If the path is for a file")
    parser.add_argument("-Sp", "--start-point", help="Determine the starting path of the search, take a path '/home' as default", type=str)
    parser.add_argument("-Vc", "--version-check", help="Check the tool version before the execution", action="store_true")
    parser.add_argument("-v", "--version", help="Print tool version and exit", action="store_true")


    args = parser.parse_args()
    folder = args.folder
    want_to_check: bool = args.version_check
    want_version: bool = args.version

    if folder == None:
        if want_version:
            print(f"version {__version__}-{__status__}")
            exit(0)
        else:
            print(f"""{colorama.Fore.CYAN}                                                     
            (   (                              )     
 (   (      )\  )\ )   (     )         (    ( /(     
 )\  )\ (  ((_)(()/(  ))\   (      (   )(   )\())(   
((_)((_))\  _   ((_))/((_)  )\  '  )\ (()\ (_))/ )\  
\ \ / /((_)| |  _| |(_))  _((_))  ((_) ((_)| |_ ((_) 
 \ V // _ \| |/ _` |/ -_)| '  \()/ _ \| '_||  _|(_-< 
  \_/ \___/|_|\__,_|\___||_|_|_| \___/|_|   \__|/__/ {colorama.Fore.MAGENTA}[{colorama.Fore.CYAN}v{colorama.Fore.GREEN}{__version__}{colorama.Fore.MAGENTA}] 
                                                     
{colorama.Fore.GREEN}A powrfull encryption tool made By {colorama.Fore.BLUE}Muhammed Alkohawaldeh{colorama.Fore.RESET}""")

            parser.print_help()
            exit(1)

    print(f"""{colorama.Fore.CYAN}                                                     
            (   (                              )     
 (   (      )\  )\ )   (     )         (    ( /(     
 )\  )\ (  ((_)(()/(  ))\   (      (   )(   )\())(   
((_)((_))\  _   ((_))/((_)  )\  '  )\ (()\ (_))/ )\  
\ \ / /((_)| |  _| |(_))  _((_))  ((_) ((_)| |_ ((_) 
 \ V // _ \| |/ _` |/ -_)| '  \()/ _ \| '_||  _|(_-< 
  \_/ \___/|_|\__,_|\___||_|_|_| \___/|_|   \__|/__/ {colorama.Fore.MAGENTA}[{colorama.Fore.CYAN}v{colorama.Fore.GREEN}{__version__}{colorama.Fore.MAGENTA}] 
                                                     
{colorama.Fore.GREEN}A powrfull encryption tool made By {colorama.Fore.BLUE}Muhammed Alkohawaldeh{colorama.Fore.RESET}, User-Mode: [{get_user_mode()}]""")

    if want_to_check:
        version_checker()   # NOTE: Check for an updates

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

            if result.strip().lower() in ['y', 'yes', 'yeah']:
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
                    if result_.strip().lower() in ['y', 'yes', 'yeah']:
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
                for _file in track(filter(folder, is_around=True, skipped=args.skipped, is_file=False, search_from=start_point)[1], description="Encrypting..."):
                     fernte_status = encrypt(_file, key)
                     if fernte_status == "reverse":
                        reveres_encryption(_file, key, 'fernet')
                     replacing_status = replace_encoding_text(_file, 'encrypted')
                     if replacing_status == "reverse":
                        reveres_encryption(_file, key, 'replacing')
                     second_layer_status = second_layer_encryption(key, _file)
                     if second_layer_status == "reverse":
                        reveres_encryption(_file, key, 'AES')
            if is_file_:

                if not all_dirs:
                    _file = filter(folder, is_around=True, skipped=None, is_file=True, search_from=start_point)
                    fernte_status = encrypt(_file, key)
                    if fernte_status == "reverse":
                        reveres_encryption(_file, key, 'fernet')
                    replacing_status = replace_encoding_text(_file, 'encrypted')
                    if replacing_status == "reverse":
                        reveres_encryption(_file, key, 'replacing')
                    second_layer_status = second_layer_encryption(key, _file)
                    if second_layer_status == "reverse":
                        reveres_encryption(_file, key, 'AES')

            else:
                for _file in track(filter(folder, is_around=True, skipped=None, is_file=False, search_from=start_point)[1], description="Encrypting..."):
                    fernte_status = encrypt(_file, key)
                    if fernte_status == "reverse":
                        reveres_encryption(_file, key, 'fernet')
                    replacing_status = replace_encoding_text(_file, 'encrypted')
                    if replacing_status == "reverse":
                        reveres_encryption(_file, key, 'replacing')
                    second_layer_status = second_layer_encryption(key, _file)
                    if second_layer_status == "reverse":
                        reveres_encryption(_file, key, 'AES')

        elif args.skipped:
            for _file in track(filter(folder, is_around=False, skipped=args.skipped, is_file=False, search_from=start_point)[1], description="Encrypting..."):
                    fernte_status = encrypt(_file, key)
                    if fernte_status == "reverse":
                        reveres_encryption(_file, key, 'fernet')
                    replacing_status = replace_encoding_text(_file, 'encrypted')
                    if replacing_status == "reverse":
                        reveres_encryption(_file, key, 'replacing')
                    second_layer_status = second_layer_encryption(key, _file)
                    if second_layer_status == "reverse":
                        reveres_encryption(_file, key, 'AES')
        else:
            if is_file_:

                if not all_dirs:
                    _file = filter(folder, is_around=False, skipped=None, is_file=True, search_from=start_point)
                    fernte_status = encrypt(_file, key)
                    if fernte_status == "reverse":
                        reveres_encryption(_file, key, 'fernet')
                    replacing_status = replace_encoding_text(_file, 'encrypted')
                    if replacing_status == "reverse":
                        reveres_encryption(_file, key, 'replacing')
                    second_layer_status = second_layer_encryption(key, _file)
                    if second_layer_status == "reverse":
                        reveres_encryption(_file, key, 'AES')

            else:
                for _file in track(filter(folder, is_around=False, skipped=None, is_file=False, search_from=start_point)[1], description="Encrypting..."):
                    fernte_status = encrypt(_file, key)
                    if fernte_status == "reverse":
                        reveres_encryption(_file, key, 'fernet')
                    replacing_status = replace_encoding_text(_file, 'encrypted')
                    if replacing_status == "reverse":
                        reveres_encryption(_file, key, 'replacing')
                    second_layer_status = second_layer_encryption(key, _file)
                    if second_layer_status == "reverse":
                        reveres_encryption(_file, key, 'AES')

        sprint(f"\n{colorama.Fore.LIGHTGREEN_EX}File Encrypted successfully{colorama.Fore.RESET}")

    elif decrypt_:
        if args.is_around:
            
            if args.skipped:
                            for _file in track(filter(folder, is_around=True, skipped=args.skipped, is_file=False, search_from=start_point)[1], description="decrypting..."):
                                second_layer_decryption(key, _file)
                                replace_encoding_text(_file, 'decrypted')
                                if not decrypt(_file, key):
                                #     print(f"{colorama.Fore.LIGHTGREEN_EX}[{_file.split('/')[-1]}] decrypted successfully{colorama.Fore.RESET}")
                                # else:
                                    sprint(f"{colorama.Fore.RED}Invalid token, most likely the password is incorrect{colorama.Fore.RESET}")
                                    exit(1)
                            sprint(f"\n{colorama.Fore.LIGHTGREEN_EX}File Decrypted successfully{colorama.Fore.RESET}")
            if is_file_:
                if not all_dirs:
                    _file = filter(folder, is_around=True, skipped=None, is_file=True, search_from=start_point)
                    second_layer_decryption(key, _file)
                    replace_encoding_text(_file, 'decrypted')
                    if not decrypt(_file, key):
                    #     print(f"{colorama.Fore.LIGHTGREEN_EX}[{_file.split('/')[-1]}] decrypted successfully{colorama.Fore.RESET}")
                    # else:
                        sprint(f"{colorama.Fore.RED}Invalid token, most likely the password is incorrect{colorama.Fore.RESET}")
                        exit(1)
                    sprint(f"\n{colorama.Fore.LIGHTGREEN_EX}File decrypted successfully{colorama.Fore.RESET}")

            else:
                for _file in track(filter(folder, is_around=True, skipped=None, is_file=False, search_from=start_point)[1], description="decrypting..."):
                        second_layer_decryption(key, _file)
                        replace_encoding_text(_file, 'decrypted')
                        if not decrypt(_file, key):
                    #     print(f"{colorama.Fore.LIGHTGREEN_EX}[{_file.split('/')[-1]}] decrypted successfully{colorama.Fore.RESET}")
                    # else:
                            sprint(f"{colorama.Fore.RED}Invalid token, most likely the password is incorrect{colorama.Fore.RESET}")
                            exit(1)
                        sprint(f"\n{colorama.Fore.LIGHTGREEN_EX}File decrypted successfully{colorama.Fore.RESET}")
                    
        elif args.skipped:
            for _file in track(filter(folder, is_around=False, skipped=args.skipped, is_file=False, search_from=start_point)[1], description="decrypting..."):
                    second_layer_decryption(key, _file)
                    replace_encoding_text(_file, 'decrypted')
                    if not decrypt(_file, key):
                    #     print(f"{colorama.Fore.LIGHTGREEN_EX}[{_file.split('/')[-1]}] decrypted successfully{colorama.Fore.RESET}")
                    # else:
                        sprint(f"{colorama.Fore.RED}Invalid token, most likely the password is incorrect{colorama.Fore.RESET}")
                        exit(1)
                    sprint(f"\n{colorama.Fore.LIGHTGREEN_EX}File decrypted successfully{colorama.Fore.RESET}")
        else:
            if is_file_:

                if not all_dirs:
                    _file = filter(folder, is_around=False, skipped=None, is_file=True, search_from=start_point)
                    second_layer_decryption(key, _file)
                    replace_encoding_text(_file, 'decrypted')
                    if not decrypt(_file, key):
                    #     print(f"{colorama.Fore.LIGHTGREEN_EX}[{_file.split('/')[-1]}] decrypted successfully{colorama.Fore.RESET}")
                    # else:
                        sprint(f"{colorama.Fore.RED}Invalid token, most likely the password is incorrect{colorama.Fore.RESET}")
                        exit(1)
                    sprint(f"\n{colorama.Fore.LIGHTGREEN_EX}File decrypted successfully{colorama.Fore.RESET}")

            else:
                for _file in track(filter(folder, is_around=False, skipped=None, is_file=False, search_from=start_point)[1], description="decrypting..."):
                        second_layer_decryption(key, _file)
                        replace_encoding_text(_file, 'decrypted')
                        if not decrypt(_file, key):
                        #     print(f"{colorama.Fore.LIGHTGREEN_EX}[{_file.split('/')[-1]}] decrypted successfully{colorama.Fore.RESET}")
                        # else:
                            sprint(f"{colorama.Fore.RED}Invalid token, most likely the password is incorrect{colorama.Fore.RESET}")
                            exit(1)
                sprint(f"\n{colorama.Fore.LIGHTGREEN_EX}File Decrypted successfully{colorama.Fore.RESET}")
    else:
         sprint(f"{colorama.Fore.RED}Please specify whether you want to encrypt the file or decrypt it.{colorama.Fore.RESET}")
         exit(1)
