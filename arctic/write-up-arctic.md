# Arctic

This is the write-up for the box Arctic that got retired at the 7th July 2017.
My IP address was 10.10.14.X while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.11    arctic.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/arctic.nmap 10.10.10.11
```

```markdown
