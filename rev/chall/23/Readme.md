# Bit-O-Asm-3 — write-up

## Goal

Find the decimal value left in `EAX` at the end of `main` and submit it as `picoCTF{n}`.

---

## Given assembly

```asm
<+0>:     endbr64 
<+4>:     push   rbp
<+5>:     mov    rbp,rsp
<+8>:     mov    DWORD PTR [rbp-0x14],edi
<+11>:    mov    QWORD PTR [rbp-0x20],rsi
<+15>:    mov    DWORD PTR [rbp-0xc],0x9fe1a
<+22>:    mov    DWORD PTR [rbp-0x8],0x4
<+29>:    mov    eax,DWORD PTR [rbp-0xc]
<+32>:    imul   eax,DWORD PTR [rbp-0x8]
<+36>:    add    eax,0x1f5
<+41>:    mov    DWORD PTR [rbp-0x4],eax
<+44>:    mov    eax,DWORD PTR [rbp-0x4]
<+47>:    pop    rbp
<+48>:    ret
```

---

## Step-by-step analysis

1. `mov DWORD PTR [rbp-0xc], 0x9fe1a`
   The constant `0x9FE1A` is stored. Convert to decimal:

   ```
   0x9FE1A = 9*16^4 + 15*16^3 + 14*16^2 + 1*16 + 10
           = 9*65536 + 15*4096 + 14*256 + 16 + 10
           = 589,824 + 61,440 + 3,584 + 16 + 10
           = 654,874
   ```

   So `[rbp-0xc] = 654,874`.

2. `mov DWORD PTR [rbp-0x8], 0x4`
   The second local is set to `4`.

3. `mov eax, DWORD PTR [rbp-0xc]`
   `EAX = 654,874`.

4. `imul eax, DWORD PTR [rbp-0x8]`
   Multiply `EAX` by `4`:

   ```
   654,874 * 4 = 2,619,496
   ```

5. `add eax, 0x1f5`
   `0x1F5 = 1*256 + 245 = 501` decimal. Add:

   ```
   2,619,496 + 501 = 2,619,997
   ```

6. The value is stored and then moved back to `EAX`, so the final `EAX = 2,619,997`.

---

## Answer (flag)

```
picoCTF{2619997}
```
