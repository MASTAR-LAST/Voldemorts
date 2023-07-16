#!/bin/bash

echo ""
echo ""

echo "Update The system..."

echo ""

sudo apt update

echo ""
echo ""

echo "Install packeges..."

echo ""

sudo pip3 install cryptography
sudo pip3 install colorama
sudo pip3 install pycryptodome
sudo pip3 install rich

echo ""
echo ""

echo "Build the tool..."

echo ""

sudo chmod u+x voldemorts.py
sudo cp voldemorts.py /bin/voldemorts
sudo mv voldemorts.py /usr/bin/voldemorts

echo ""
echo ""

echo "Done !"

echo ""

