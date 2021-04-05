# Alternative way to exploit Obscurity

## HTTP (Port 8080)

### Getting SuperSecureServer.py with Directory Traversal

There is a **Directory Traversal vulnerability** on the website and with that it is possible to get the _SuperSecureServer.py_ code, instead of fuzzing for hidden directories.

As this is a Python server, the code that runs the web server is often one directory up from the static pages:
```
GET /../SuperSecureServer.py HTTP/1.1
Host: 10.10.10.168:8080
(...)
```

This shows the Python code in the response.
