# Beep

This is the write-up for the box Beep that got retired at the 1st September 2017.
My IP address was 10.10.14.X while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.7    beep.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/beep.nmap 10.10.10.7
```

```markdown
