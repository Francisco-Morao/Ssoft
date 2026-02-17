# Challenge `I challenge you for a race` writeup

- Vulnerability: What type of vulnerability is being exploited
  - The vulnerability being exploited is a TOCTOU race condition via a symlink attack.
- Where: Where is the vulnerability present
  - The vulnerability is specifically in using access() to check permissions and then later calling fopen() on the same path. This creates a TOCTOU race condition allowing a symlink attack.
- Impact: What results of exploiting this vulnerability
  - Exploiting this vulnerability allows the attacker to trick the program into reading any file on the system, even files the program normally should not have permission to access.

## Steps to reproduce

1. Prepare a harmless file by creating a “good” file that the program is supposed to legitimately read.
3. Start rapidly switching the symlink by continuously changing pointer so that it alternates between harmless file and the protected file. This creates the race condition.
4. Repeatedly run the vulnerable program. Call the program in a loop and always feed it the filename pointer. Each run gives the program another chance to hit the race window. 
5. Finally, we detect when the race succeeds.
6. Result: Unauthorized file disclosure, the program outputs the flag, demonstrating that the TOCTOU symlink race allows an attacker to bypass file access checks.

[(POC)](I_challenge_you_for_a_race.sh)
