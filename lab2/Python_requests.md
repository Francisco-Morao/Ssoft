# Challenge `Python Request` writeup

- Vulnerability: What type of vulnerability is being exploited
  - It is a Business Logic vulnerability.
- Where: Where is the vulnerability present
  - /hello : starts the game and reveals initial state
  - /more : updates the stored values until they match
  - /finish : accepts completion without verifying that the client actually solved anything
- Impact: What results of exploiting this vulnerability
  - The attacker can complete the challenge and gain its rewards without performing the intended logic, compromising the integrity of the system.

## Steps to reproduce

1. Start a new session and access the /hello endpoint to initialize the game and receive the target number.
2. Parse the response to extract:
- the target value
- the current sum provided in the first lines of the response.
3. Repeatedly call the /more endpoint to receive new random positive or negative numbers:
4. After each /more request, parse the returned value and update the running sum stored client-side.
5. Continue calling /more until the client‑computed running sum equals the target value.
6. Once the current sum matches the target, call the /finish endpoint.
7. Result: The server returns the flag, demonstrating that the game’s state can be fully manipulated.

[(POC)](python_requests.py)
