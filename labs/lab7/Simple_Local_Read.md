# Challenge `Simple Local Read` writeup

- Vulnerability: What type of vulnerability is being exploited
  - Format String Vulnerability
- Where: Where is the vulnerability present
  - In `vuln()` function at `printf(buffer);`. The buffer is fully controlled by user input via `read()` in `main()`.
- Impact: What results of exploiting this vulnerability
  - An attacker can read arbitrary stack memory, including sensitive values.
Specifically, this vulnerability allows leaking the value of secret_value, which contains the flag returned by `get_flag()`, even though it is never explicitly printed.

## Steps to reproduce

1. Connect to the challenge service `nc mustard.stt.rnl.tecnico.ulisboa.pt 25191`

2. Inspect the stack using format specifiers by sending a payload that prints multiple stack values using `%x`:
```
AAAA.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x
---------------
Output:

AAAA.0804c000.ffffdcd8.0804930a.0804c060.f7eed483.0804c000.0804d008.00000000.0804c000.ffffdce8.0804935f
```

This reveals the contents of stack slots following the format string.

3. So `secret_value` is a local variable in `vuln()`. It is a pointer returned by `get_flag()`
From stack inspection, the 7th stack argument contains a pointer to the flag string

4. Read the flag using `%s`, which prints a string from a pointer we use `%7$s` to dereference the pointer and print the string it points to:
```
AAAA.%7$s
```
5. Result: The program prints the contents of `secret_value`.The flag is successfully leaked despite never being printed in the source code
