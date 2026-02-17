# Challenge `Short Local Read` writeup

- Vulnerability: What type of vulnerability is being exploited
  - Format String Vulnerability
- Where: Where is the vulnerability present
  - In `vuln()` function at `printf(buffer);`. The buffer is fully controlled by user input via `read()` in `main()`.
- Impact: What results of exploiting this vulnerability
  - An attacker can read arbitrary stack memory, including sensitive values. Specifically, this vulnerability allows leaking the value of secret_value, which contains the flag returned by `get_flag()`, even though it is never explicitly printed.

## Steps to reproduce

1. Connect to the challenge service `nc mustard.stt.rnl.tecnico.ulisboa.pt 25192`

2. Because the input buffer is extremely small, we cannot enumerate the stack.
Instead, we try nearby positional arguments using at most 4 characters.

Example attempts:
```
%5$s
%6$s
%7$s
```

3. Successful payload was `%7$s`. This format string instructs printf to read the 7th argument on the stack, treat it as a pointer to a string and finally print the contents of that memory

4. Result: The program prints the contents of `secret_value`.The flag is successfully leaked despite never being printed in the source code
