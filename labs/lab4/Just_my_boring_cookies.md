# Challenge `Just my boring cookies` writeup

- Vulnerability: What type of vulnerability is being exploited
  - Cross-Site Scripting (XSS), specifically Reflected XSS.
- Where: Where is the vulnerability present
  - In the the search URL query parameter, more specific:
    ```js
    http://ssof2526.challenges.cwte.me:25251/?search=<payload>
    ```
- Impact: What results of exploiting this vulnerability
  - Execution of malicious JavaScript in the victim’s browser
  - Theft of session cookies and user data
  - Account hijacking and actions performed on behalf of the user

## Steps to reproduce

1. Place the following command in the search field to see that exists a vulnerability:
```js
<h1>hi</h1>
```
2. Then, enter the following payload in the search field to execute JavaScript and access cookies:
```js
<script>alert(document.cookie);</script> 
``` 