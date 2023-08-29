#!/bin/bash

# Copyright (c) 2023 Muhammed Alkohawaldeh
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT
echo ""

echo "Installing Files..."

sudo mkdir $HOME/.vtemp
sudo wget $1 -O $HOME/.vtemp/v.temp.zip

echo ""
echo ""

echo "Extract Files..."
sudo unzip $HOME/.vtemp/v.temp.zip

echo ""
echo ""

echo "Rebuilding Tool..."
sudo chmod u+x $2/voldemorts.sh
sudo ./$2/voldemorts.sh



