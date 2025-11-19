# Challenge `Python Request` writeup

- Vulnerability: What type of vulnerability is being exploited
  - It is a Insecure state management vulnerability
- Where: Where is the vulnerability present
  - /hello : starts the game and reveals initial state
  - /more : returns incremental numbers, allowing state enumeration
- Impact: What results of exploiting this vulnerability
  - Exploiting this vulnerability allows an attacker to systematically reach the target sum without guessing blindly. By repeatedly querying /more and using the state preserved via cookies, the attacker can reliably trigger /finish and obtain the flag.
- NOTE: Any other observation

## Steps to reproduce

1. Start a new session and access the /hello endpoint to initialize the game and receive the target number.
2. Parse the response to extract:
- the target value
- the current sum provided in the first lines of the response.
3. Repeatedly call the /more endpoint to receive new random positive or negative numbers:
4. After each /more request, parse the returned value and update the running sum stored client-side.
5. Continue calling /more until the client‑computed running sum equals the target value.
6. Once the current sum matches the target, call the /finish endpoint.
7. Result: The server returns the flag, demonstrating that the game’s state can be fully manipulated and completed by enumeration.

[(POC)](python_requests.py)
