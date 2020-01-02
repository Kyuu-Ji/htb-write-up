# Mirai

This is the write-up for the box Mirai that got retired at the 10th February 2018.
My IP address was 10.10.14.24 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.48    mirai.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/mirai.nmap 10.10.10.48
```

```markdown
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.7p1 Debian 5+deb8u3 (protocol 2.0)
| ssh-hostkey:
|   1024 aa:ef:5c:e0:8e:86:97:82:47:ff:4a:e5:40:18:90:c5 (DSA)
|   2048 e8:c1:9d:c5:43:ab:fe:61:23:3b:d7:e4:af:9b:74:18 (RSA)
|   256 b6:a0:78:38:d0:c8:10:94:8b:44:b2:ea:a0:17:42:2b (ECDSA)
|_  256 4d:68:40:f7:20:c4:e5:52:80:7a:44:38:b8:a2:a7:52 (ED25519)
53/tcp open  domain  dnsmasq 2.76
| dns-nsid:
|_  bind.version: dnsmasq-2.76
80/tcp open  http    lighttpd 1.4.35
|_http-server-header: lighttpd/1.4.35
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The name of the box is a hint because **Mirai** was a botnet that was first found in 2016 that took control of many different websites and devices.
It scanned the internet for IoT devices and tried default credentials to take control of them.

So guessing that there will some default credentials on this box.

## Checking HTTP (Port 80)

When browsing to the web page with the IP address, it shows nothing and gives an HTTP error code 404.
But when browsing to it with the domain name _mirai.htb_ it shows the following text:
```markdown
Website Blocked

Access to the following site has been blocked:
mirai.htb
If you have an ongoing use for this website, please ask the owner of the Pi-hole in your network to have it whitelisted.
This page is blocked because it is explicitly contained within the following block list(s):
Go back Whitelist this page Close window
Generated Thu 9:20 PM, Jan 02 by Pi-hole v3.1.4
```

It displays a blocked page by the software **Pi-hole**.
This is an application that blocks internet traffic based on DNS queries and acts as a DNS sinkhole and is most often installed on **Raspberry Pi** devices.

When looking at the HTML source code on the page, it displays a link to the following URLs which confirms the existence of a Pi-hole:
```markdown
http://pi.hole/pihole
http://pi.hole/admin
```

The path _/admin_ is a default path for the Pi-hole and it is possible to browse there to get the Pi-hole dashboard.

## Checking SSH (Port 22)

Now knowing that this is a **Raspberry Pi** and assume it has default credentials, lets try the default credentials for it.
The credentials for a non-configured Raspberry Pi are:
```markdown
username: pi
password: raspberry
```

This works and we are logged in as the user _pi_.

## Privilege Escalation

If this device is not configured properly, then it is possible to switch to root by using the command `sudo su -`.
This works and we are root because _pi_ can execute anything as root!
```markdown
User pi may run the following commands on localhost:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: ALL
```

### Reading the flags

The _root.txt_ has unusual content in it:
```markdown
I lost my original root.txt! I think I may have a backup on my USB stick...
```

The command `df -h` shows the device _/dev/sdb_ is mounted on _/media/usbstick_ that has a directory and a file in it:
- Empty _lost+found_ directory
- damnit.txt
```markdown
Damnit! Sorry man I accidentally deleted your files off the USB stick.
Do you know if there is any way to get them back?

-James
```

To recover the files, we output the `strings` of the _/dev/sdb_ device:
```markdown
strings /dev/sdb
```

Now it shows the flag of _root.txt_.
