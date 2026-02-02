<div style="
  border:2px solid #ff3b3b;
  background:#2a0f0f;
  padding:16px;
  border-radius:12px;
  color:#ffd6d6;
  font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,sans-serif;
">

  <div style="display:flex; align-items:center; gap:10px; margin-bottom:12px;">
    <span style="font-size:22px;">⚠️</span>
    <h3 style="margin:0; color:#ff5c5c; letter-spacing:0.5px;">
      Critical Safety Warnings
    </h3>
  </div>

  <div style="
    border:1px solid #ff3b3b;
    background:#3a1414;
    padding:12px;
    border-radius:10px;
    font-weight:700;
    color:#ffe1e1;
    margin-bottom:14px;
  ">
    STOP: Never encrypt an already-encrypted file.  
    This tool generates a new salt for every encryption pass and overwrites the previous salt stored in
    <code style="background:#1b0a0a; padding:2px 6px; border-radius:6px; color:#ffd6d6;">/usr/volde_info/</code>.  
    Without the original salt, the first layer of encryption becomes mathematically impossible to unlock.
  </div>

  <ul style="margin:0; padding-left:20px; line-height:1.65;">
    <li style="margin-bottom:10px;">
      <b style="color:#ffb3b3;">Absolute Path Dependency:</b>
      The salt filename is linked to the file’s <b>absolute path</b>.  
      If an encrypted copy is saved to a Desktop folder, the absolute path hash changes, which may prevent the tool
      from finding the correct salt for decryption.
    </li>

    <li style="margin-bottom:10px;">
      <b style="color:#ffb3b3;">Status:</b>
      Fixing this “link-break” by moving to a <b>per-file salt architecture</b> is the top priority for
      <code style="background:#1b0a0a; padding:2px 6px; border-radius:6px; color:#ffd6d6;">v2.0.0</code>.
    </li>

    <li>
      <b style="color:#ffb3b3;">Timeline:</b>
      The v2.0.0 release may be delayed due to limited developer availability and is currently estimated for
      <b>Q4 2026</b>.  
      A full rewrite in <b>Rust</b> is planned for improved performance and reliability.
    </li>
  </ul>

  <div style="
    margin-top:14px;
    padding:12px;
    border:1px dashed rgba(255, 59, 59, 0.8);
    border-radius:10px;
    background:#240d0d;
  ">
    <div style="font-weight:800; color:#ff9a9a; margin-bottom:6px;">
      Salt Recovery Guide (Linux/macOS)
    </div>

    <div style="font-size:0.95em; color:#ffd6d6; line-height:1.55;">
      If a salt file was overwritten, the only way to recover the encrypted data is to restore the previous salt from
      <code style="background:#1b0a0a; padding:2px 6px; border-radius:6px; color:#ffd6d6;">/usr/volde_info/</code>.
    </div>

    <ul style="margin:8px 0 0 0; padding-left:20px; font-size:0.95em; line-height:1.55;">
      <li>
        <b>macOS:</b> Check
        <code style="background:#1b0a0a; padding:2px 6px; border-radius:6px; color:#ffd6d6;">tmutil listlocalsnapshots /</code>
        to locate local system snapshots.
      </li>
      <li>
        <b>Linux:</b> Use
        <code style="background:#1b0a0a; padding:2px 6px; border-radius:6px; color:#ffd6d6;">ext4magic</code>
        or
        <code style="background:#1b0a0a; padding:2px 6px; border-radius:6px; color:#ffd6d6;">debugfs</code>
        to attempt recovery from the filesystem journal.
      </li>
    </ul>
  </div>

</div>


# Voldemorts
**Voldemorts** is a huge and powerful tool capable of encrypting files in various formats with *Fernet* and _AES_ encrypting algorithms, salt with a default value of 16 bytes that can be changed and a password to encrypt and decrypt these files. 🔐
![Screenshot_2024-01-24_09-58-59](https://github.com/MASTAR-LAST/Voldemorts/assets/79379000/7d744b57-bd01-4f09-83ef-5bd565ce0ce2)

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

>Last Test in **_No Date_** for version **No Version**

## Installation 📥
#### Install the tool with Git ![Git](https://github.com/MASTAR-LAST/Science/assets/79379000/1594eb5f-fc68-4255-9c3d-5f6340a045f2)

```bash
git clone https://github.com/MASTAR-LAST/Voldemorts.git && cd Voldemorts && sudo chmod u+x installer.sh && ./installer.sh
```


### Using instructions

```bash
sudo voldemorts [directory name] --encrypt --salt-size 128
```

# Roadmap 🗺️
1. **Hybrid encryption with *AES&Fernet*** - [*Done*] ✅
2. **Auto reversing for encryption layers if one is failed** - [*Done*] ✅
3. **Version tracker** - [*Done*] ✅ 
4. **Fast file searching** - [*Done*] ✅
5. **Auto decrypting side script** 🔄
6. **Windows supporting** 🔄
7. **Password auto-generation flag with length and character set** - [*Done*] ✅
8. **Caesar encryption layer** 🔄
9. **RSA encryption flag** 🔄
10. **Get hash flag** - [*Done*] ✅
11. **More search options** 🔄
12. **Stop at the first file you find flag** 🔄 - [*In progress*]
13. **Double checking password** - [*Done*] ✅
14. **Expiry date for the file** 🔄
15. **Electronic signature** 🔄
16. **Split the file into parts depending on the memory size** 🔄
17. **Make an encrypted copy of the file/directory** - [*Done*] ✅
18. **Fast Encryption/Decryption files** 🔄
19. **Remove the image metadata flag before encrypting it** 🔄

# Last Release Info 🕑

## What's new in v1.3.0? ☄️
### New Features 🌟

1. **Hash function optimization** 🪛
2. **Unwanted code cleaning** 🧹
3. **Replace `-c` with `-cs` flag** ❄️
4. **Copy file options** 💫
5. **Improving the installer for fresh devices** 🤖
6. **The ability to specify the groups from which the password is generated**
7. **Passwords Log File** 🕵🏼‍♂️
8. **Configuration file** 🔗

### Fixed Bugs 🪲
**issue numbers:** [#14](https://github.com/MASTAR-LAST/Voldemorts/issues/14) 📍

> **You can find password log file & configuration file in /usr/volde_info as a hidden files**

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
**Support Email:** twisters50team@gmail.com 📧

## Note  📌
**Use this tool in a super user mood.** 🥷🏼

**The supported file formats table has a test time and version in its footer, any version that is released without updating the table could be not safe for any file formats _except text files._**