# CTF

This is the write-up for the box CTF that got retired at the 20th July 2019.
My IP address was 10.10.14.91 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.122    ctf.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/ctf.nmap 10.10.10.122
```

```markdown
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 fd:ad:f7:cb:dc:42:1e:43:7d:b3:d5:8b:ce:63:b9:0e (RSA)
|   256 3d:ef:34:5c:e5:17:5e:06:d7:a4:c8:86:ca:e2:df:fb (ECDSA)
|_  256 4c:46:e2:16:8a:14:f6:f0:aa:39:6c:97:46:db:b4:40 (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16
|_http-title: CTF
```

## Checking HTTP (Port 80)

On the webpage we get a text that says the following:
> As part of our SDLC, we need to validate a proposed authentication technology, based on software token, with a penetration test.
Please login to do your test.
This server is pretected against some kind of threats, for instance, bruteforcing.
[...]
A list of banned IP is available here...

If we click on _here_ we get the output of a _top_ command and a list of banned IPs. Both information are not interesting, so we get to the _Login_ part of the page.

We are greated with an input for an **Username** and an **OTP**. If we input a non valid used we get the message _User test not found_.
When testing for special characters with _Burpsuite_ by URL encoding strings multiple times, we get only one time URL encoded strings. This means there is some kind of blacklist in the background.

If we check the source-code of the login page we get a hint that says:
> at the moment we have choosen an already existing attribute in order to store the token string (81 digits)

After some research on the internet for **Software Token Linux** we get to the conclusion that the software [stoken](https://www.systutorials.com/docs/linux/man/1-stoken/) was used.
On that page you can find that the numeric string is **81 digits**, just like the hint told us.
And the box name **CTF** stands for _compressed token format_.
Now we know that we will use this software for this token but first we need to enumerate usernames.

### Enumerating usernames

Bruteforcing / Extensive Fuzzing won't help us as this will get us on a blacklist, so we need another way.
But we need to fuzz a little bit anyway.
Fuzzing for some usernames doesn't get us any results and fuzzing for special characters neither because of the blacklist we found about earlier.

As double URL encoded characters get us different responses, we will fuzz for that with the wordlist from _Seclists_ **doble-uri-hex.txt**.
In this wordlist there are all 256 ASCII characters but double URL encoded.

Short explanation of double URL encoding
>This is the double URL encoded character for A:
%2541

>An application decodes %25 first (thats %) and then we are left with **%41**.
This will be decoded after and then we are left with **A** 

The command with _wfuzz_ looks like this:
```markdown
wfuzz --hw 233 -d 'inputUsername=FUZZ&inputOTP=1234' -w doble-uri-hex.txt  hxxp://10.10.10.122/login.php
```

The results are:
- %2500 = Null Byte
- %2528 = (
- %2529 = )
- %255a = *
- %255c = \

Looking at these characters it becomes clear that these are often used in **LDAP queries**!
