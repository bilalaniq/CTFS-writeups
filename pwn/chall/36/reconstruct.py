import struct
words = [0x67616c66,0x6c6f737b,0x7d646576,0x415d0000,0xffaa14c0,0xf7f78e14,0x565cbecc,0xf7fdfb60]
s = b''.join(struct.pack('<I', w) for w in words)
flag = s.split(b'\x00',1)[0].decode()   # stop at first NUL
print(flag)   
