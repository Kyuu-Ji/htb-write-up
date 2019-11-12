# Optimum

This is the write-up for the box Optimum that got retired at the 28th October 2017.
My IP address was 10.10.14.23 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.8    optimum.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/optimum.nmap 10.10.10.8
```
