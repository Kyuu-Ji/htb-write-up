# Querier

This is the write-up for the box Querier that got retired at the 22nd June 2019. 
My IP address was 10.10.13.X while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.125    querier.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/querier.nmap 10.10.10.125
```

```markdown
