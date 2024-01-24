#!/bin/bash

# Copyright (c) 2023 Muhammed Alkohawaldeh
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

echo ""
echo ""

echo -e "Today is \033[44m" `date` + "\033[0m"

echo ""

echo -e "\033[1;93mUpdate The system...\033[0;39m"

echo ""

sudo apt-get update -y

echo ""
echo ""

echo -e "\033[102mSources check...\033[0m"

echo ""

sudo apt-get install python3 python3-pip

echo ""
echo ""

echo -e "\033[1;93mInstall necessary packages...\033[0;39m"

echo ""

sudo pip3 install beautifulsoup4
sudo pip3 install fake-useragent
sudo pip3 install cryptography
sudo pip3 install pycryptodome
sudo pip3 install colorama
sudo pip3 install requests
sudo pip3 install rich

pip install beautifulsoup4
pip install fake-useragent
pip install cryptography
pip install pycryptodome
pip install colorama
pip install requests
pip install rich

sudo apt-get install unzip

echo ""
echo ""

echo -e "\033[1;93mBuild the tool...\033[0;39m"

echo ""

echo -e "\033[1;93mBuilding call command...\033[0;39m"

echo ""

sudo chmod u+x voldemorts.py
sudo cp voldemorts.py /bin/voldemorts
sudo mv voldemorts.py /usr/bin/voldemorts

echo -e "\033[1;93mBuilding the helping script...\033[0;39m"

echo ""

sudo chmod u+x tool_updater25T.sh
sudo cp tool_updater25T.sh /bin/tool_updater25T
sudo mv tool_updater25T.sh /usr/bin/tool_updater25T

echo ""
echo ""

echo -e "\033[1;93mBuilding the configuration file...\033[0;39m"

echo ""

sudo mv volde_info /usr/volde_info

echo ""
echo ""

echo -e "\033[1;97mCleanning...\033[0m"

echo ""

sudo apt-get autoremove

echo ""
echo ""

echo -e "\033[1;92mDone !\033[0m"

echo ""

