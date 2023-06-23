#!/bin/bash

echo ""
echo ""

echo "Update The system"

echo ""

sudo apt update

echo ""
echo ""

echo "Install packeges"

echo ""

pip install cryptography
pip install colorama

sudo chmod u+x voldemorts.py
sudo mv voldemorts.py /usr/local/bin

echo ""
echo ""

echo "Done !"

echo ""

