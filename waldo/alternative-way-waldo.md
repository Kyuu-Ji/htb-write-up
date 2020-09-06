# Alternative way to exploit Waldo

## Escape Restricted Bash

There is another way to escape the **Restriced Shell** instead of using the _logMonitor_ binary.

As the user _nobody_ we use the SSH command to become _monitor_, but this time executing SSH with a command at the end:

```markdown
ssh -i .monitor monitor@127.0.0.1 bash
```

This will start a SSH session and execute `bash` and the user was never in the restricted shell.
