#!/bin/bash

echo "Update The system"

sudo apt update

echo "Install packeges"

pip install getpass
pip install cryptography

mv voldemorts.py /usr/local/bin

echo "Done !"

