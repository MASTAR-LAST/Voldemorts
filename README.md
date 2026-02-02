<div style="border:2px solid #ff3b3b; background:rgba(255, 0, 0, 0.08); padding:16px; border-radius:10px; font-family: sans-serif;">

<h3 style="margin:0 0 15px 0; color:#ff3b3b; text-transform: uppercase;">
  ⚠️ Critical Safety Warnings
</h3>

<div style="border: 1px solid #ff3b3b; padding: 12px; border-radius: 8px; margin-bottom: 16px; font-weight: bold;">
  STOP: Never encrypt an already-encrypted file. This tool generates a new salt for every encryption pass and overwrites the previous salt stored in /usr/volde_info/. Without that original salt, the first layer of encryption becomes mathematically impossible to unlock.
</div>

<ul style="margin:0; padding-left:20px; line-height: 1.6;">
  <li style="margin-bottom:10px;">
    <b>Absolute Path Dependency:</b> The salt filename is linked to the file's <b>absolute path</b>. If you create an encrypted copy, it is saved to a specific folder on the <b>Desktop</b>—this change in location changes the absolute path hash, making the tool unable to find the correct salt for decryption.
  </li>
  <li>
    <b>Status:</b> Solving this "link-break" by moving to a per-file salt architecture is the top priority for <code>v2.0.0</code>.
  </li>
</ul>

<div style="margin-top:15px; padding:12px; border:1px dashed #ff3b3b; border-radius:8px;">
  <b style="color:#ff3b3b; font-size:0.9em; text-transform:uppercase;">Salt Recovery Guide (Linux/macOS)</b>
  <p style="margin:5px 0 0 0; font-size:0.9em;">
    If you have accidentally overwritten a salt file, the only way to recover your data is to restore the old salt from <code>/usr/volde_info/</code>:
  </p>
  <ul style="margin:5px 0 0 0; padding-left:20px; font-size:0.85em;">
    <li><b>macOS:</b> Check <code>tmutil listlocalsnapshots /</code> in Terminal to find hidden system backups.</li>
    <li><b>Linux:</b> Use <code>ext4magic</code> or <code>debugfs</code> to attempt recovery of the overwritten hidden salt file from the filesystem journal.</li>
  </ul>
</div>

</div>

<div style="height: 20px;"></div>

<div style="border:2px solid #3b82f6; background:rgba(59, 130, 246, 0.05); padding:16px; border-radius:10px; font-family: sans-serif;">

<h3 style="margin:0 0 15px 0; color:#3b82f6; text-transform: uppercase;">
  🚀 Upcoming in v2.0.0 (Roadmap)
</h3>

<table style="width:100%; border-collapse: collapse; font-size: 1em;">
  <tr>
    <td style="vertical-align:top; width:50%; padding-right:15px; border-right: 1px solid rgba(59, 130, 246, 0.2);">
      <b style="color:#3b82f6;">Security & Reliability</b>
      <ul style="margin:10px 0 10px 0; padding-left:20px; line-height:1.5;">
        <li><b>Secure Wipe:</b> Option to shred/overwrite the original file after creating an encrypted copy.</li>
        <li>Salt per file (Fixed Absolute Path bug)</li>
        <li>Salt size: 16B → 32B</li>
        <li>Fixed password predictability vulnerability</li>
        <li>SSL certificate verification for updates</li>
      </ul>
    </td>
    <td style="vertical-align:top; width:50%; padding-left:15px;">
      <b style="color:#3b82f6;">UX & Performance</b>
      <ul style="margin:10px 0 10px 0; padding-left:20px; line-height:1.5;">
        <li>Automated file backups</li>
        <li>Image metadata stripping</li>
        <li>Load passwords from external files</li>
        <li>Configurable salt/backup paths (.config.ini)</li>
        <li>Improved memory management</li>
      </ul>
    </td>
  </tr>
</table>

<div style="border-top:1px solid rgba(59, 130, 246, 0.2); margin-top:15px; padding-top:12px; font-size:0.95em; line-height: 1.5;">
  <b>Timeline:</b> Estimated release in <b>Q4 2026</b>.<br/>
  <b>Future:</b> A full <b>Rust rewrite</b> is planned for improved performance and reliability.
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