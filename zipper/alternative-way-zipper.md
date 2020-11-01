# Alternative way to exploit Zipper

## Privilege Escalation to root

After having access to the _zipper_ box with the user _zabbix_ there is another way to escalate privileges to root without being _zapper_ first.
Instead of using the misconfiguration in the **systemd** process, the _zabbix-service_ has another vulnerability.

When checking the `strings` of _/home/zapper/utils/zabbix-service_ there is one line that executes _"systemctl daemon-reload && systemctl start zabbix-agent"_.
By checking `ltrace` it shows that it is running with a relative path:
```markdown
ltrace ./zabbix-service
```
```markdown
(...)
system("systemctl daemon-reload && syste"...
(...)
```

This means that by **PATH Hijacking** and creating our own _systemctl_ command, before it executes the real one, it is possible to execute arbitrary code.

Creating own _systemctl_ in _/tmp_:
```markdown
/bin/bash
```

Exporting _/tmp_ to path:
```markdown
export PATH=/tmp:$PATH
```

When executing _systemctl_ now, it will look into _/tmp_ first and execute _/bin/bash_.
So when executing _./zabbix-service_ it will execute our _systemctl_ to start bash as root.
