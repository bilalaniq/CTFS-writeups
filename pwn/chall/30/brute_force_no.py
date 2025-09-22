#!/usr/bin/python3
from pwn import *
import sys

class bcolors:
    GREEN = '\u001b[32m'
    RED   = '\u001b[31m'
    ENDC  = '\033[0m'

# -------------------------
# Args check
# -------------------------
if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} remote|local <count>")
    sys.exit(0)

mode = sys.argv[1].lower()
count = int(sys.argv[2])

# -------------------------
# Config
# -------------------------
REMOTE_HOST = 'shape-facility.picoctf.net'
REMOTE_PORT = 64338          # <-- put the actual port here
elf = ELF('./vuln')

random_sequence = []


for i in range(count):
    for j in range(1, 101):

        # open connection
        if mode == "remote":
            r = remote(REMOTE_HOST, REMOTE_PORT)
        else:
            r = elf.process()

        # skip intro
        r.recvline()
        r.recvline()

        # replay already found numbers
        for number in random_sequence:
            r.recvuntil(b'What number would you like to guess?\n')
            r.sendline(str(number).encode())
            r.recvuntil(b'Name? ')
            r.sendline(b'whitesnake')

        # now try candidate j
        r.recvuntil(b'What number would you like to guess?\n')
        r.sendline(str(j).encode())

        response = r.recvline(timeout=1)
        if response and b'Nope' not in response:
            random_sequence.append(j)
            r.close()
            break

        r.close()

print(random_sequence)
