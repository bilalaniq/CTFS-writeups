from pwn import *
import time

t1 = int(time.time()*1000)
r = remote("verbal-sleep.picoctf.net", 55986)
t2 = int(time.time()*1000)
print("RTT:", t2-t1, "ms")
