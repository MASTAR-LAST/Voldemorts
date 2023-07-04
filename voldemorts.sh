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
sudo -H pip3 install cython

echo ""
echo ""

echo "Build the tool..."

echo ""

sudo chmod u+x voldemorts.py
sudo cython3 voldemorts.py --embed -3
sudo PYTHONLIBVER=python$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')$(python3-config --abiflags)
gcc -Os $(python3-config --includes) voldemorts.c -o voldemorts $(python3-config --ldflags) -l$PYTHONLIBVER
sudo mv voldemorts /usr/local/bin
sudo rm voldemorts.c

echo ""
echo ""

echo "Done !"

echo ""

