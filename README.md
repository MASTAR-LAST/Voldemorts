# Voldemorts
**Voldemorts** is a powerful tool capable of encrypting files in various formats with *Fernet* and *AES* encrypting with a salt with a default value of 16 bytes that can be changed and a password to encrypt and decrypt these files. 🔐
![Screenshot_2023-08-03_01-48-16](https://github.com/MASTAR-LAST/Voldemorts/assets/79379000/9fffdab4-c3a2-4bd9-a432-f07213fd3050)

<p align="center">
  <a href="https://www.linkedin.com/in/muhammed-al-kohawaldeh-2a1295245/" alt="LinkedIn">
  <img src="https://img.shields.io/badge/LinkedIn-Mohammed%20Alkohawaldeh-purple?logo=linkedin&logoColor=blue&color=blue" />
  </a>
  <a href="https://discord.com/channels/1059139195127480420/1059139196075384956" alt="Chat on Discord">
   <img src="https://img.shields.io/discord/808045925556682782.svg?logo=discord&colorB=00d37d" target="blank" />
  </a>
  <a href="https://www.paypal.com/paypalme/MASTALAST" alt="Paypal">
  <img src="https://img.shields.io/liberapay/receives/TheAlgorithms.svg?logo=Paypal" target="blank" />
  </a>
  <a href="https://twitter.com/twisters50" alt="Twitter">
  <img src="https://img.shields.io/twitter/follow/The_Algorithms?label=Follow us&style=social" />
  </a>
  <a href="#license" alt="Twitter">
  <img src="https://img.shields.io/github/license/MASTAR-LAST/Science?color=grean" />
  </a>
  <a href="" alt="Twitter">
  <img src="https://img.shields.io/badge/Development_status-slow-red" />
  </a>
  <a href="" alt="Twitter">
  <img src="https://img.shields.io/liberapay/receives/muhammed.svg?logo=liberapay">
  </a>
</p>



# Supported systems 🛠
| System       | Supporting    |
| :----------- | :-----------: |
| Windows      | Not Supported ❌|
| Linux        | Supported ✅    |
| Mac          | Supported ✅    |

# Supported file formats 🗂
| Type      | Formats |
| :----------- | :-----------: |
| Documents 📑     | .doc .docx .odp .ods .odt .pdf .pptx .rtf .xls .xlsx .ppt .djvu .ott .txt .csv .srt|
| E-Books 📚   | .azw3 .equb .fb2 .lrf .mobi .snb .pdb |
| Programming 🖥  | .bat .htaccess .yaml .class .cs .css .go .h .html .js .pl .py .rb .sh .sql .swift .test .vb .java .c .cpp .kml .json|
| Videos 🎥   | .asf .avi .f4v .flv .hevc .m2ts .m2v .m4v .mjpeg .mkv .mov .mp4 mpeg .mpg .mts .mxf .ogv .swf .ts .vob .webm .wmv .wtv .3gp |
| Fonts 📝   | .bin .cff .dfont .otf .pfb .ps .sfd .ttf .woff |
| Images 📸   | .bmp .svg .jpg .tif .gif .png .cr2 .dng .erf .heic .heif .jfif .jp2 .nef .nrw .orf .pef .pes .raf .rw2 .webp .cur .dds .exr .fts .hdr .ico .jpe .jps .mng .pam .pbm .pcd .pcx .pfm .pgm .pico .pict .pnm .ppm .psd .ras .sfw .sgi .tga .wbmp .wpg .x3f .xbm .xcf .xpm .xwd |
| Audios 🔊   | No tests yet 🔬 |
| Extra Formats 🔰  | .exe .dll .ocx .drv |



## Installation 📥
#### Install the tool with Git ![Git](https://github.com/MASTAR-LAST/Science/assets/79379000/1594eb5f-fc68-4255-9c3d-5f6340a045f2)

```bash
git clone https://github.com/MASTAR-LAST/Voldemorts.git && cd Voldemorts && sudo chmod u+x voldemorts.sh && ./voldemorts.sh
```


### Using instructions

```bash
sudo voldemorts [folder name] --encrypt --salt-size 128
```
### Help
```bash
            (   (                              )     
 (   (      )\  )\ )   (     )         (    ( /(     
 )\  )\ (  ((_)(()/(  ))\   (      (   )(   )\())(   
((_)((_))\  _   ((_))/((_)  )\  '  )\ (()\ (_))/ )\  
\ \ / /((_)| |  _| |(_))  _((_))  ((_) ((_)| |_ ((_) 
 \ V // _ \| |/ _` |/ -_)| '  \()/ _ \| '_||  _|(_-< 
  \_/ \___/|_|\__,_|\___||_|_|_| \___/|_|   \__|/__/ 
                                                     
A powerful encryption tool made By Muhammad Alkohawaldeh
usage: voldemorts.py [-h] [-Ss SALT_SIZE] [-e] [-d] [-a] [-s [SKIPPED ...]] [-f] [-Sp START_POINT] [-Vc] [-v] [folder]

File Encrypting Script with a Password

positional arguments:
  folder                Folder to encrypt/decrypt

options:
  -h, --help            show this help message and exit
  -Ss SALT_SIZE, --salt-size SALT_SIZE
                        If this is set, a new salt with the passed size is generated, take 16 as default
  -e, --encrypt         Whether to encrypt the file, only -e or -d can be specified.
  -d, --decrypt         Whether to decrypt the file, only -e or -d can be specified.
  -a, --is-around       If is around, the tool will encrypt/decrypt all the files that is with it in the same folder
  -s [SKIPPED ...], --skipped [SKIPPED ...]
                        If there is any file you want to ignored it
  -f, --is-file         If the path is for a file
  -Sp START_POINT, --start-point START_POINT
                        Determine the starting path of the search, take a path '/home' as default
  -Vc, --version-check  Check the tool version before the execution
  -v, --version         Print tool version and exit
```
# Roadmap 🗺️
1. **Hybrid encryption with *AES&Fernet*** - [*Done*] ✅
2. **Auto reversing for encryption layers if one is failed** - [*Done*] ✅
3. **Version tracker** - [*Done*] ✅ 
4. **Auto decrypting side script** 🔄
5. **Fast file searching** 🔄
6. **Windows supporting** 🔄
7. **Password auto-generation flag with length and character set** 🔄
8. **Caesar encryption layer** 🔄
9. **RSA encryption flag** 🔄
10. **Get hash flag** 🔄

# Changelog 🕑

## What's new in v1.0.0? ☄️
### New Features 🌟

1. **Stable release.**  🛡
2. **Good error handling** 💫
3. **Useful error messages** 💪
4. **Writing a report when an error occurred** 📃
5. **Auto reversing for encryption layers if one is failed** 🧠
6. **Version checker** 👀
7. **Auto updates for the tool** 🤖
8. **Version flag** 🚩
9. **User permissions checker** 👾

### Fixed Bugs 🪲
**issue numbers:** [#4](https://github.com/MASTAR-LAST/Voldemorts/issues/4) 📍

# License 📑

MIT License

Copyright (c) 2023 Muhammed AL-kohwaldeh

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Project Status

### The development of this project has become slow due to the busyness of the current developer. 💤
### Any requests for contributions are very welcome. ❤️‍🔥


## Support 📨
**Support Email:** twisters50team@gmail.com 

## Note  📌
**Use this tool in a super user mood.**

###  📛WARNING📛: ⚠️DO NOT ENCRYPT THE SAME FILE TWO TIMES OR YOU WILL BE UNABLE TO DECRYPT IT AGAIN⚠️
