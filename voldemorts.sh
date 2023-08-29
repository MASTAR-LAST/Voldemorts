#!/bin/bash

# Copyright (c) 2023 Muhammed Alkohawaldeh
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

echo ""
echo ""

echo "Today is " `date`
echo "Update The system..."

echo ""

sudo apt-get update

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

