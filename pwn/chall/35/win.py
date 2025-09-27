import subprocess

with open("payload.bin", "rb") as f:
    payload = f.read()

subprocess.run([r".\chall.exe"], input=payload)
