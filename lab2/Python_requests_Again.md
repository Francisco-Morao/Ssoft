# Challenge `Python Request Again` writeup

- Vulnerability: What type of vulnerability is being exploited
  - It is a Insecure Client-Side State Manipulation vulnerability
- Where: Where is the vulnerability present
  - /hello : initializes the game and sets the `remaining_tries` cookie
  - /more : decrements and checks the `remaining_tries` cookie
- Impact: What results of exploiting this vulnerability
  - Exploiting this vulnerability allows an attacker to bypass the server-imposed limit on the number of attempts by modifying the cookie. As a result, the attacker can continue calling /more until they achieve the target state and then successfully call /finish to obtain the flag.
- NOTE: Any other observation

## Steps to reproduce

1. Start a new session and access the /hello endpoint to initialize the game and receive the remaining_tries cookie.
2. Observe that the server sets a limited number of attempts in the cookie: remaining_tries=1.
3. Modify the cookie value locally to a large number to bypass the limitation.
4. Repeatedly call the /more endpoint to continue receiving new numbers and updating the current sum.
5. Continue obtaining more numbers until the sum matches the target.
6. Once the target is reached, call the /finish endpoint.
7. Result: The server accepts the success and returns the flag, demonstrating that altering the cookie bypasses the intended attempt limit.

[(POC)](python_request_Again.py)
