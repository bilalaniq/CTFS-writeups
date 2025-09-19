

## **asm1**

**Description:**
We are given a small function in x86 assembly and asked:

> *What does `asm1(0x6fa)` return?*
> Submit the flag as a hexadecimal value (starting with `0x`).
> ⚠️ Note: This flag is **not** in the usual `picoCTF{}` format. 

**HINT:** 

[assembly conditions](https://www.tutorialspoint.com/assembly_programming/assembly_conditions.htm)

---

### Provided Assembly

```asm
asm1:
    push   ebp
    mov    ebp,esp
    cmp    DWORD PTR [ebp+0x8],0x3a2
    jg     0x512 <asm1+37>

    cmp    DWORD PTR [ebp+0x8],0x358
    jne    0x50a <asm1+29>
    mov    eax,DWORD PTR [ebp+0x8]
    add    eax,0x12
    jmp    0x529 <asm1+60>

<+29>:
    mov    eax,DWORD PTR [ebp+0x8]
    sub    eax,0x12
    jmp    0x529 <asm1+60>

<+37>:
    cmp    DWORD PTR [ebp+0x8],0x6fa
    jne    0x523 <asm1+54>
    mov    eax,DWORD PTR [ebp+0x8]
    sub    eax,0x12
    jmp    0x529 <asm1+60>

<+54>:
    mov    eax,DWORD PTR [ebp+0x8]
    add    eax,0x12

<+60>:
    pop    ebp
    ret
```

---

### Step-by-Step Analysis

1. The function checks the input parameter (stored at `[ebp+0x8]`).

2. **First comparison:**

   ```asm
   cmp [ebp+0x8], 0x3a2
   jg high_branch
   ```

   * If `arg > 0x3a2`, execution jumps to the high branch (`<+37>`).
   * Otherwise, it goes into the “low branch” handling `0x358`.

3. **Low branch (`arg ≤ 0x3a2`):**

   * If `arg == 0x358`, return `arg + 0x12`.
   * Else, return `arg - 0x12`.

4. **High branch (`arg > 0x3a2`):**

   * If `arg == 0x6fa`, return `arg - 0x12`.
   * Otherwise, return `arg + 0x12`.

---

### Case: `asm1(0x6fa)`

* Input = `0x6fa` (1786 decimal).
* First check: `0x6fa > 0x3a2` → take the high branch.
* Next check: `arg == 0x6fa` → true.
* Execution:

  ```asm
  mov eax, 0x6fa
  sub eax, 0x12
  ```
* Result: `0x6fa - 0x12 = 0x6e8`.

---

### Final Answer

The function returns:

```
0x6e8
```

⚠️ Submit exactly this (without `picoCTF{}`).

