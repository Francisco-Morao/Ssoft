# Challenge `Secure by Design.py` writeup

- Vulnerability: What type of vulnerability is being exploited
  - It is a Insecure authentication mechanism vulnerability
- Where: Where is the vulnerability present
  - It is present in the root endpoint(/) which sets and validates the `user` cookie to determine access level
- Impact: What results of exploiting this vulnerability
  - Exploiting this vulnerability allows an attacker to modify the user cookie to "admin", granting full unauthorized access to the application’s administrative functionality.
- NOTE: Any other observation

## Steps to reproduce

1. Start a new session and access the root endpoint / to initialize the cookie storage.
2. Submit any username via a POST request to the same endpoint.
3. Modify the cookie value to the Base64‑encoded string of "admin".
4. Send another request to / using the modified cookie.
5. Result: The server believes the client is authenticated as an administrator and reveals admin‑only functionality or protected content.

[(POC)](secureByDesign.py)
