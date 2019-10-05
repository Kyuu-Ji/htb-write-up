# Help

This is the write-up for the box Help that got retired at the 8th June 2019.
My IP address was 10.10.14.10 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.121    help.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/help.nmap 10.10.10.121
```

```markdown
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e5:bb:4d:9c:de:af:6b:bf:ba:8c:22:7a:d8:d7:43:28 (RSA)
|   256 d5:b0:10:50:74:86:a3:9f:c5:53:6f:3b:4a:24:61:19 (ECDSA)
|_  256 e2:1b:88:d3:76:21:d4:1e:38:15:4a:81:11:b7:99:07 (ED25519)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
3000/tcp open  http    Node.js Express framework
|_http-title: Site doesn't have a title (application/json; charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

On the webpage that is running on port 80 we see the Apache2 default page, so we use gobuster to enumerate hidden paths:
```markdown
gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt dir -u http://10.10.10.121
```

We get a path called **/support** that shows us a ticket system with the name **Help Desk Software by HelpDeskZ**.
So we can check if there are known vulnerabilities for this software:
```markdown
searchsploit helpdeksz
```

There are two vulnerabilites that both work for the version lower than _1.0.2_ so we need to find out what the version is.

- HelpDeskZ 1.0.2 - Arbitrary File Upload
- HelpDeskZ < 1.0.2 - (Authenticated) SQL Injection / Unauthorized File Download

After searching for this application we find out that it is a open-source program that is hosted on GitHub. Downloading the README.md of the webpage works and discloses it is version 1.0.2.


### Arbitratry File Upload exploit

Analyzing the **Arbitratry File Upload exploit** we can see how the application obfuscates filenames:
```markdown
/controllers <https://github.com/evolutionscript/HelpDeskZ-1.0/tree/006662bb856e126a38f2bb76df44a2e4e3d37350/controllers>/*submit_ticket_controller.php - Line 141*
$filename = md5($_FILES['attachment']['name'].time()).".".$ext;
```

It takes the file name, the system time and the extension and combining all of them to a MD5 hashsum.
When we upload a file we know the name and the upload time and thus can calculate this ourselves.

Now lets _Submit a Ticket_ and attach a PHP file with it. In my case I am going to take the script _php-reverse-shell.php_ and let it call my IP and port 9001.
![Uploading a PHP file]()

It says that the file is not allowed but the author of the script said it gets uploaded anyway so you can ignore that warning.

Now we could execute the Python exploit but it won't work because the script looks for the time on our local machine and not the one on the box. 
We can find out the time of the server by analyzing any HTTP response with Burpsuite.

We will change the Python exploit so it makes a response to the box and takes its time instead of ours. This script will be in this folder named **exploit-help.py**.
```markdown
python exploit-help.py http://10.10.10.121/support/uploads/tickets/ php-reverse-shell.php
```

After uploading the PHP reverse shell again and then executing the exploit we get a reverse shell!

## Privilege Escalation

We are logged in as the user _help_ and can read user.txt and should now execute any enumeration script to get an attack surface.
What strikes out is that the kernel version 4.4.0-116-generic is old and has privilege escalation vulnerabilites.

We can copy [CVE-2017-16995](https://www.exploit-db.com/exploits/44298) and compile it on the box:
```markdown
gcc privesc.c -o privesc
```

After executing it, we are root on the box!
