# Alternative way to exploit Hawk

## Privilege Escalation to user

After starting a reverse shell as _www-data_ there is a way to login as _daniel_ on the box.

By looking through the **Drupal** configuration files in _/var/www/html_ there is a configuration file called _sites/default/settings.php_ in which is a password:
> drupal4hawk

Trying this password on the user _daniel_ via SSH works:
```markdown
ssh daniel@10.10.10.102
```

The shell of this user is a _Python shell_ but we can get switch to bash:
```python
import os

os.system("bash")
```
