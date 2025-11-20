# Challenge `PwnTools Sockets` writeup

- Vulnerability: What type of vulnerability is being exploited
  - It is a Business Logic vulnerability.
- Where: Where is the vulnerability present
  - "MORE" : leaks internal state and allows unlimited progression toward the target.
- Impact: What results of exploiting this vulnerability
  - By repeatedly issuing the MORE command and monitoring the server’s state, an attacker can reliably reach the target condition and then execute FINISH to obtain the flag, bypassing the intended challenge mechanics.

## Steps to reproduce

1. Establish a remote connection to the service.
2. Read the initial target and current values provided by the server upon connection.
3. Continuously send the `MORE` command.
4. After each response, parse the newly returned CURRENT value.
5. Repeat until the CURRENT value equals the target value.
6. Once the values match, send `FINISH`
7. Result: The server responds with the flag, demonstrating that the challenge can be solved solely by abusing the unrestricted state‑progression logic.

[(POC)](pwnTools_sockets.py)
