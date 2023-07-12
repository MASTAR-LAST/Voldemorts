#!/usr/bin/env python3
import sys
import time
import colorama

from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def sprint(text, second=0.03):
    for line in text + '\n':
        sys.stdout.write(line)
        sys.stdout.flush()
        time.sleep(second)

def secend_layer_encryption(password, filename):
    try:
        salt = b'\x15\x0b_\xfd\x84"P\x8cp3r\xceY\xc2I\x07'

        key = PBKDF2(password, salt, dkLen=16)

        with open(filename, "rb") as file:
            file_data = file.read()

            cipher = AES.new(key, AES.MODE_CBC)
            ciphered_data = cipher.encrypt(pad(file_data, AES.block_size))

        with open(filename, 'wb') as _file:
            _file.write(salt + cipher.iv + ciphered_data)
    except:
        sprint(f"{colorama.Fore.RED}Something goes wrong !!{colorama.Fore.RESET}")
        exit(1)

def secend_layer_decryption(password, filename):
    try:
        with open(filename, 'rb') as encryptfile:
            file_data = encryptfile.read()

            salt = file_data[:16]
            iv = file_data[16:32]
            decrypt_data = file_data[32:]

            key = PBKDF2(password, salt, dkLen=16)

            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            original_data = unpad(cipher.decrypt(decrypt_data), AES.block_size)

        with open(filename, 'wb') as _encryptfile:
            _encryptfile.write(original_data)
    except:
        sprint(f"{colorama.Fore.RED}Something goes wrong !!{colorama.Fore.RESET}")
        exit(1)
