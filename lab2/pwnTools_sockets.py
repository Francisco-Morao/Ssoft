from pwn import *

SERVER = "mustard.stt.rnl.tecnico.ulisboa.pt"
PORT = 25055

### run a remote process
s = remote(SERVER, PORT)

s.recvuntil(b"get to ")
target = s.recvline().decode().replace('.', "")

s.recvuntil(b"CURRENT = ").decode()
current = s.recvline().decode().replace('.', "")

while current != target:

    s.sendline(b"MORE")
    s.recvuntil(b"CURRENT = ").decode()
    current = s.recvline().decode().replace('.', "")

s.sendline(b"FINISH")
print(s.recvall().decode())