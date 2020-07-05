# Alternative way to exploit Crimestoppers

## Privilege Escalation to root

After we are _dom_ there is another way to get the parameter to get root without reverse engineering.

When looking at this box from an **incident response** perspective then it is important to know when the incident happened.
The file _whiterose.txt_ was placed on the box at December 23 while the email from WhiteRose is from December 16. Lets list all files that were placed between these dates:
```markdown
find / -type f -newermt 2017-12-15 ! -newermt 2017-12-24 -ls 2>/dev/null
```

The **Apache2** logs were modified in that timeframe and _dom_ has permission to read those:
```markdown
zcat /var/log/apache2/access.log.[234.* | grep -v 'OPTIONS\|HEAD\|POST\'
```

When analyzing them, there is also the _"FunSociety"_ GET parameter in there that can be used to get the root shell.
