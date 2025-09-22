#!/usr/bin/python3
from pwn import *
import sys

if len(sys.argv) != 2:
    warn(f"Usage: {sys.argv[0]} remote|local")
    exit(0)

mode = sys.argv[1]

# -------------------------
# Remote / local setup
# -------------------------
REMOTE_HOST = 'shape-facility.picoctf.net'
REMOTE_PORT = 58314

elf = ELF('./vuln')

class Guesser:
    def __init__(self, proc):        
        self.found = None
        self.proc = proc
        
    def start(self):
        self.proc.recvlines(3)  # skip intro
        for guess in range(-4097, 4097):
            self.proc.recvline()  # skip prompt
            info(f"Guessing {guess}...")
            self.proc.sendline(str(guess).encode())
            resp = self.proc.recvline(timeout=1)
            if resp:
                resp_text = resp.decode(errors="ignore").strip()
                self.proc.recvline()  # skip following line
                if "Congrats" in resp_text:
                    self.found = guess
                    break            
        return self.found

# -------------------------
# Open connection
# -------------------------
if mode.lower() == "remote":
    p = remote(REMOTE_HOST, REMOTE_PORT)
else:
    p = elf.process()

# -------------------------
# Start guessing
# -------------------------
guesser = Guesser(p)
magic_number = guesser.start()
if magic_number is None:
    log.failure("Magic number not found")
else:
    log.success(f"Magic number found: {magic_number}")

# Optional: keep interactive to see the server
p.interactive()
