# Challenge `Guess Big Number` writeup

- Vulnerability: What type of vulnerability is being exploited
  - It would be a Brute-force attack optimized with a binary search, in other words a Binary Search Attack
- Where: Where is the vulnerability present
  - /number/{v} endpoint leaks comparison feedback ("Higher!", "Lower!"), enabling a binary-search enumeration attack to discover the secret number.
- Impact: What results of exploiting this vulnerability
  - Because the endpoint leaks directional hints, an attacker can reliably and efficiently recover the correct number in only a small number of requests.

## Steps to reproduce

1. Navigate to the service’s root endpoint to obtain a session cookie. 
2. Start sending guesses to the vulnerable endpoint
3. Observe the server’s responses:
**"Higher!"**, 
**"Lower!"**,
or the success message when the correct number is reached.
4. Use these responses to perform a binary search, adjusting the guess range based on each hint.
5. Continue the process until the server reveals the correct secret number.
6. Result: The attacker can reliably recover the server's hidden number in logarithmic time.

[(POC)](guess_big_number.py)
