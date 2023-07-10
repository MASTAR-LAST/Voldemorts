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

pip install cryptography
pip install colorama

echo ""
echo ""

echo "Build the tool..."

echo ""

sudo chmod u+x voldemorts.py
sudo mv voldemorts.py /bin/voldemorts
sudo mv slayar.py /bin/voldemorts

echo ""
echo ""

echo "Done !"

echo ""

