# OneTwoSeven

This is the write-up for the box OneTwoSeven that got retired at the 31st August 2019.
My IP address was 10.10.14.209 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.133    onetwoseven.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/onetwoseven.nmap 10.10.10.133
```

```markdown
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 48:6c:93:34:16:58:05:eb:9a:e5:5b:96:b6:d5:14:aa (RSA)
|   256 32:b7:f3:e2:6d:ac:94:3e:6f:11:d8:05:b9:69:58:45 (ECDSA)
|_  256 35:52:04:dc:32:69:1a:b7:52:76:06:e3:6c:17:1e:ad (ED25519)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Page moved.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

We get a lot of information on the webpage which not all of it will be relevant. We can read about a IPv6 service that is coming soon.
A SFTP service and DoS protection.

After clicking on _Sign Up_ we get a username and a password for a SFTP service, where we can upload pages via **sftp://onetwoseven.htb** that is hosted on **hxxp://onetwoseven.htb/~ots-2ZWE1MDE/**.
```markdown
Username: ots-2ZWE1MDE
Password: fa6ea501
```

### Checking the SFTP service

We can login with the given credentials on this SFTP service.
```markdown
sftp ots-2ZWE1MDE@10.10.10.133
```

There we find the static HTML file of our webpage and we have the permission to upload files. The application only allows static files and blocks PHP files, so we don't have code execution yet.
By looking at the _help_ we see that we can create symlink. With that we could read files from the server like this:

```markdown
symlink / testpath
```

We created a symbolic link from the root path to a directory on our webpage which means we got access to /etc/passwd on **hxxp://onetwoseven.htb/~ots-2ZWE1MDE/testpath/etc/passwd**.

Let's look for the files in the directory where this web application runs in **hxxp://onetwoseven.htb/~ots-2ZWE1MDE/Testerman/var/www/html-admin/**. 
In this directory we find the file **.login.php.swp** that we can download and examine.
```markdown
file .login.php.swp
```

It says that it is a _VIM swap file_. Such files are created whenever we edit something a VIM but don't quit it gracefully. In these cases the files are kind of caches as this swap files that we can restore.
```markdown
mv login.php.swp .login.php.swp
vim login.php

r (to recover)
```

And now we can read the file.

#### Analyzing the PHP file

This PHP file has some very interesting information:
- If the servers port is _not equal_ to 60080 then close the connection
- Username: ots-admin
- Password: 11c5a42c9d74d5442ef3cc835bda1b3e7cc7f494e704a10d0de426b2fbe5cbd8

Let's check for that port with Nmap:
```markdown
nmap -p 60080 10.10.10.133
```

It says it is a filtered port and no other information, but we will use that port soon.

The hash we got has 64 characters and is probably a SHA256 hash. We can either crack this manually but we find it on hashes.org:
> Homesweethome1


