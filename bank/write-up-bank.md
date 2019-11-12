# Bank

This is the write-up for the box Bank that got retired at the 22nd September 2017.
My IP address was 10.10.14.23 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.29    bank.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/bank.nmap 10.10.10.29
```

```markdown
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 08:ee:d0:30:d5:45:e4:59:db:4d:54:a8:dc:5c:ef:15 (DSA)
|   2048 b8:e0:15:48:2d:0d:f0:f1:73:33:b7:81:64:08:4a:91 (RSA)
|   256 a0:4c:94:d1:7b:6e:a8:fd:07:fe:11:eb:88:d5:16:65 (ECDSA)
|_  256 2d:79:44:30:c8:bb:5e:8f:07:cf:5b:72:ef:a1:6d:67 (ED25519)
53/tcp open  domain  ISC BIND 9.9.5-3ubuntu0.14 (Ubuntu Linux)
| dns-nsid:
|_  bind.version: 9.9.5-3ubuntu0.14-Ubuntu
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking DNS (Port 53)

Lets enumerate some DNS information with _nslookup_:
```markdown
nslookup

> SERVER 10.10.10.29

Default server: 10.10.10.29
Address: 10.10.10.29#53

> 127.0.0.1

1.0.0.127.in-addr.arpa  name = localhost.

> 10.10.10.29

** server can't find 29.10.10.10.in-addr.arpa: NXDOMAIN

> bank.htb

Server:         10.10.10.29
Address:        10.10.10.29#53

Name:   bank.htb
Address: 10.10.10.29
```

Reverse lookup is not active and the hostname _bank.htb_ responds to the IP.
Lets try a **DNS Zone Transfer** with _dig_:
```markdown
dig axfr bank.htb @10.10.10.29

# Output
bank.htb.               604800  IN      SOA     bank.htb. chris.bank.htb. 2 604800 86400 2419200 604800
bank.htb.               604800  IN      NS      ns.bank.htb.
bank.htb.               604800  IN      A       10.10.10.29
ns.bank.htb.            604800  IN      A       10.10.10.29
www.bank.htb.           604800  IN      CNAME   bank.htb.
bank.htb.               604800  IN      SOA     bank.htb. chris.bank.htb. 2 604800 86400 2419200 604800
```

We get some interesting subdomains that we will put into our hosts file.

## Checking HTTP (Port 80)

On the web page we see the default Apache2 Ubuntu installation page.
As we found out there is a domain name, we can browse to the web page with the domain name _bank.htb_ and we get a login page.
This is called **Virtual Host Routing**.

![Bank login page](https://kyuu-ji.github.io/htb-write-up/bank/bank_login.png)

We use **Gobuster** to enumerate hidden paths on this page with the PHP extension:
```markdown
gobuster -u http://bank.htb/ dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php
```

There are these directories that could be interesting:
- /uploads (Status: 301)
- /inc (Status: 301)
- /index.php (Status: 302)
- /support.php (Status: 302)
- /balance-transfer (Status: 200)

### Method 1 - Ignore redirects

With Burpsuite we can look on the web pages that redirect us by changing the HTTP response code from _302 Found_ to HTTP code _200 OK_.

This is the index.php page:

![Bank index page](https://kyuu-ji.github.io/htb-write-up/bank/bank_index.png)

This is the support.php page:

![Bank support page](https://kyuu-ji.github.io/htb-write-up/bank/bank_support.png)

We can upload code on the support.php to get command execution on the box.


### Method 2 - Intended way

The directory _balance-transfers_ that we found has many of these files in it:

![Bank balance-transfers page](https://kyuu-ji.github.io/htb-write-up/bank/bank_balance-transfers.png)

This goes way down. There are around 1000 of these files. Looking at one of them they hold this content:
```markdown
++OK ENCRYPT SUCCESS
+=================+
| HTB Bank Report |
+=================+

===UserAccount===
Full Name: czeCv3jWYYljNI2mTedDWxNCF37ddRuqrJ2WNlTLje47X7tRlHvifiVUm27AUC0ll2i9ocUIqZPo6jfs0KLf3H9qJh0ET00f3josvjaWiZkpjARjkDyokIO3ZOITPI9T
Email: 1xlwRvs9vMzOmq8H3G5npUroI9iySrrTZNpQiS0OFzD20LK4rPsRJTfs3y1VZsPYffOy7PnMo0PoLzsdpU49OkCSSDOR6DPmSEUZtiMSiCg3bJgAElKsFmlxZ9p5MfrE
Password: TmEnErfX3w0fghQUCAniWIQWRf1DutioQWMvo2srytHOKxJn76G4Ow0GM2jgvCFmzrRXtkp2N6RyDAWLGCPv9PbVRvbn7RKGjBENW3PJaHiOhezYRpt0fEV797uhZfXi
CreditCards: 5
Transactions: 93
Balance: 905948 .
===UserAccount===
```

Lets download all of them, to examine them easier in the shell.
```markdown
wget -r http://bank.htb/balance-transfer/
```

By sorting them by file size we see that most of them have either 583, 584 or 585 bytes except for one that has 257 bytes.
```markdown
wc -c \*.acc | sort -n -r
```

The file with the name **68576f20e9732f1b2edc4df5b8533230.acc** has only 257 bytes and has this content:
```markdown
--ERR ENCRYPT FAILED
+=================+
| HTB Bank Report |
+=================+

===UserAccount===
Full Name: Christos Christopoulos
Email: chris@bank.htb
Password: !##HTBB4nkP4ssw0rd!##
CreditCards: 5
Transactions: 39
Balance: 8842803 .
===UserAccount===
```

When trying this credentials on the login page we get logged in.
