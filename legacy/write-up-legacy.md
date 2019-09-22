# Legacy

This is the write-up for the box Legacy that was released at the 15th March 2017.

Let's put this in our hosts file:
```markdown
10.10.10.4    legacy.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/legacy.nmap 10.10.10.4
```

```markdown
PORT     STATE  SERVICE       VERSION
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open   microsoft-ds  Windows XP microsoft-ds
3389/tcp closed ms-wbt-server
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: mean: 5d00h28m04s, deviation: 2h07m16s, median: 4d22h58m04s
|_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:83:73 (VMware)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2019-09-27T14:23:02+03:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)
```

##  Checking SMB

As this is a Windows XP client with a SMB port open it should be fairly easy to find an exploit for that.
We can use the Metasploit module **exploit/windows/smb/ms08_067_netapi**, configure the host and run it.

This works and starts a meterpreter session. We can either read the flags with the built-in commands from meterpreter or start a _shell_ and work with that.
Our session is running as **NT Authority\SYSTEM** so we can read the contents of all users!
