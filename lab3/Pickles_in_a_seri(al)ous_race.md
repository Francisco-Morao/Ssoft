# Challenge `Pickles in a seri(al)ous race` writeup

- Vulnerability: What type of vulnerability is being exploited
  -The vulnerability being exploited here is Insecure Deserialization (Pickle RCE)
- Where: Where is the vulnerability present
  - The vulnerability is the unsafe deserialization of attacker-controlled input using **pickle.loads()** when reading a Classy note. This allows remote code execution (RCE).
- Impact: What results of exploiting this vulnerability
  - The vulnerability allows arbitrary code execution, which can lead to unauthorized file access and full compromise of the service.

## Steps to reproduce

1. Craft a malicious pickle payload, by preparing a note whose content is a pickle object that executes a system command when deserialized.
2. Write this malicious note in FREE mode. In FREE mode, the server saves raw text, so the malicious pickle bytes are stored without being executed.
3. Use threads to repeatedly switch between write (FREE) and read (CLASSY).
The attacker spawns threads that rapidly write the malicious note (FREE mode) and then read it (CLASSY mode). This creates a race condition where CLASSY mode may deserialize the malicious payload before it is overwritten.
4. Eventually, the read occurs while the note contains the malicious pickle.
At the right timing, CLASSY mode calls pickle.loads() on the attacker‑controlled data.
5. Result: The pickle payload executes, letting the attacker run arbitrary commands, such as reading restricted files.

[(POC)](Pickles_in_a_seri(al)ous_race.py)
