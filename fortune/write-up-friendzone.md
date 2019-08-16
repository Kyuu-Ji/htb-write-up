# FriendZone

This is the write-up for the box FriendZone that got retired at the 13th July 2019.

Let's put this in our hosts file:
```markdown
10.10.10.132    friendzone.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/friendzone.nmap 10.10.10.123
```
