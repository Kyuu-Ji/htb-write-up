# Arkham

This is the write-up for the box Arkham that got retired at the 10th August 2019.
My IP address was 10.10.13.112 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.130    arkham.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/arkham.nmap 10.10.10.130
```

```markdown
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
8080/tcp open  http          Apache Tomcat 8.5.37
| http-methods: 
|_  Potentially risky methods: PUT DELETE
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Mask Inc.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1s, deviation: 0s, median: 1s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2019-08-15 13:48:33
|_  start_date: N/A
```

## Checking HTTP (Port 80 and port 8080)

The web page on port 80 has just the default IIS site, so let's check port 8080.

### Checking HTTP (Port 8080)

The Apache Tomcat website contains some company website where most links are not working but one does.
If we click on _subscription_ we get forwarded to the path /userSubscribe.faces.

We send that to Burpsuite to examine this more. The parameter **javax.faces.ViewState** has this string:

```markdown
javax.faces.ViewState=wHo0wmLu5ceItIi%2BI7XkEi1GAb4h12WZ894pA%2BZ4OH7bco2jXEy1RcVjhMDN4sZB70KtDtngjDm0mNzA9qHjYerxo0jW7zu11SwN%2Ft3lVW5GSeZ1PEA3OZ3jFUE%3D
```

If we Bas64 decode this we get non-readable strings, so it seems like this is encrypted in any way. As we now don't know how right now, we can continue with the other services.

## Checking SMB (Port 445)

Try which SMB shares are on the server with the _anonymous_ user:

```markdown
smbmap -H 10.10.10.130 -u anonymous
```

We enumerated some shares and have read access on:
- IPC$
- BatShare
- Users

```markdown
smbclient -U anonymous //10.10.10.130/batshare
```

There is one file named **appserver.zip**, so we download this and unzip it our local machine.

```markdown
unzip appserver.zip
```

### Checking appserver.zip

In this file there are two files:
- IMPORTANT.txt
- backup.img

IMPORTANT.txt says:
> Alfred, this is the backup image from our linux server. Please see that The Joker or anyone else doesn't have unauthenticated access to it. - Bruce

It seems like we should mount the _backup.img_ to get more information. Let's check what kind of file this is:

```markdown
file backup.img
backup.img: LUKS encrypted file, ver 1 [aes, xts-plain64, sha256] UUID: d931ebb1-5edc-4453-8ab1-3d23bb85b38e
```

With the tool **cryptsetup** we can examine LUKS encrypted files and this commands tells us that the payload offset is at 4096.
```markdown
cryptsetup luksDump backup.img
```

With that information we can get the header:
```markdown
dd if=backup.img of=arkham-luks bs=512 count=4097
```

Now we need to crack the password:
```markdown
hashcat -m 14600 arkham-luks /usr/share/wordlists/rockyou.txt
```

The cracked password is:
> batmanforever

Now we can mount the _backup.img_:
```markdown
cryptsetup luksOpen backup.img arkham
mount /dev/mapper/arkham /mnt
```

In the _/mnt_ directory we now have the Folder **Mask** in which we find pictures of Batman characters and some tomcat configuration files in the folder _tomcat-stuff_.
After comparing the files _web.xml_ and _web.xml.bak_, we see that those files are very different. In the latter file we find this information:

```markdown
org.apache.myfaces.SECRET: SnNGOTg3Ni0=
org.apache.myfaces.MAC_ALGORITHM: HmacSHA1
```

We write a script that can decrypt the value in the _javax.faces.ViewState_ parameter. I call this script **arkham-exploit.py** and can be found in this repository.

