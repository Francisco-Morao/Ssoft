# Challenge `Another jackpot` writeup

- Vulnerability: What type of vulnerability is being exploited
  - The script exploits a race condition in authentication/session state
- Where: Where is the vulnerability present
  - The vulnerability is in the **/login** route, where the session’s username is set before validating the password, causing a time window where the session is treated as logged in.
- Impact: What results of exploiting this vulnerability
  - Successful exploitation results in full authentication bypass and privilege escalation to admin, allowing unauthorized access to sensitive data and any protected functionality.

## Steps to reproduce

1. Create a session with the server. The script starts a requests.Session() so all requests share the same JTOKEN, so they have the same session.
2. Spam **/login** with wrong passwords in many threads. These repeated login attempts cause a race condition where the server briefly sets the session username to "admin" before checking the password.
3. Spam **/jackpot** in parallel threads, these requests constantly check whether the session temporarily thinks we are admin.
4. Eventually, a **/jackpot** request arrives at the exact moment the session is in the “admin” state.
5. Result: The race condition makes the server leak the protected secret to an unauthenticated attacker.

[(POC)](Another_jackpot.py)
