#!/bin/bash

echo "\n\nUpdate The system\n"

sudo apt update

echo "\n\nInstall packeges\n"

pip install cryptography

sudo mv voldemorts.py /usr/local/bin

echo "\n\nDone !"

