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

sudo pip3 install beautifulsoup4
sudo pip3 install fake-useragent
sudo pip3 install cryptography
sudo pip3 install pycryptodome
sudo pip3 install colorama
sudo pip3 install requests
sudo pip3 install rich

sudo apt-get install unzip

echo ""
echo ""

echo "Build the tool..."

echo ""

sudo chmod u+x voldemorts.py
sudo cp voldemorts.py /bin/voldemorts
sudo mv voldemorts.py /usr/bin/voldemorts

sudo chmod u+x tracker_voldemort3600k.sh
sudo cp tracker_voldemort3600k.sh /bin/tracker_voldemort3600k
sudo mv tracker_voldemort3600k.sh /usr/bin/tracker_voldemort3600k

echo ""
echo ""

echo "Done !"

echo ""

