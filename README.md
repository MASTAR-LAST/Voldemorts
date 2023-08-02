# Voldemorts
Voldemorts, It is a powerful tool capable of encrypting files in various formats with Fernet and AES encrypting with a salt with a default value of 16 bytes that can be changed and a password to encrypt and decrypt these files.
![Screenshot_2023-08-03_01-48-16](https://github.com/MASTAR-LAST/Voldemorts/assets/79379000/9fffdab4-c3a2-4bd9-a432-f07213fd3050)

# Supported systems
| System       | Supporting    |
| :----------- | :-----------: |
| Windows      | Not Supported |
| Linux        | Supported     |
| Mac          | Supported     |

# Supported Files formats
| Type      | Foramts |
| :----------- | :-----------: |
| Documents      | .doc .docx .odp .ods .odt .pdf .pptx .rtf .xls .xlsx .ppt .djvu .ott .txt .csv .srt|
| E-Books   | .azw3 .equb .fb2 .lrf .mobi .snb .pdb |
| Programming   | .bat .htaccess .yaml .class .cs .css .go .h .html .js .pl .py .rb .sh .sql .swift .test .vb .java .c .cpp .kml .json|
| Videos   | .asf .avi .f4v .flv .hevc .m2ts .m2v .m4v .mjpeg .mkv .mov .mp4 mpeg .mpg .mts .mxf .ogv .swf .ts .vob .webm .wmv .wtv .3gp |
| Fonts    | .bin .cff .dfont .otf .pfb .ps .sfd .ttf .woff |
| Images   | .bmp .svg .jpg .tif .gif .png .cr2 .dng .erf .heic .heif .jfif .jp2 .nef .nrw .orf .pef .pes .raf .rw2 .webp .cur .dds .exr .fts .hdr .ico .jpe .jps .mng .pam .pbm .pcd .pcx .pfm .pgm .pico .pict .pnm .ppm .psd .ras .sfw .sgi .tga .wbmp .wpg .x3f .xbm .xcf .xpm .xwd |
| Audios   | No tests yet |
| Extra Formats  | .exe .dll .ocx .drv |



## Installation
Install the tool with git

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
                                                     
A powrfull encryption tool made By Muhammed Alkohawaldeh
usage: voldemorts [-h] [-Ss SALT_SIZE] [-e] [-d] [-a] [-s SKIPPED] [-f] [-Sp START_POINT] folder

File Encryptor Script with a Password

positional arguments:
  folder                Folder to encrypt/decrypt

options:
  -h, --help            show this help message and exit
  -Ss SALT_SIZE, --salt-size SALT_SIZE
                        If this is set, a new salt with the passed size is generated, take 16 as default
  -e, --encrypt         Whether to encrypt the file, only -e or -d can be specified.
  -d, --decrypt         Whether to decrypt the file, only -e or -d can be specified.
  -a, --is-around       If is around, the tool will encrypt/decrypt all the files that is with it in the same
                        folder
  -s SKIPPED, --skipped SKIPPED
                        If there is any file you want to ignored it
  -f, --is-file         If the path is for a file
  -Sp START_POINT, --start-point START_POINT
                        Determine the starting path of the search, take a path '/home' as default
                                                                                                   
```

## Note
**use this tool in super user mood.**

