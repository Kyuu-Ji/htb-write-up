# Alternative way to exploit Ypuffy

## Privilege Escalation

After being logged in as _alice1978_ there is another way to escalate privileges to root.

In this version of OpenBSD is a [vulnerability in the X.org service](https://github.com/0xdea/exploits/blob/master/openbsd/raptor_xorgasm).
```markdown
searchsploit openbsd xorg
```

After uploading this script to the box and executing it, the binary _/usr/local/bin/pwned_ can be executed and starts a session as root.
