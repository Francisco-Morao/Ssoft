# Challenge `I will take care of this site` writeup

- Vulnerability: What type of vulnerability is being exploited
  - SQL Injection, Authentication Bypass
- Where: Where is the vulnerability present
  - It is present at the login form (username/password fields), where user-supplied input is directly concatenated into an SQL query without parameterization or input validation.
- Impact: What results of exploiting this vulnerability
  - Bypass authentication without knowing valid credentials
  - Log in as the administrator
  - Access the administrator’s profile
  - Read sensitive information such as the admin password
  - Full account compromise and disclosure of confidential data

## Steps to reproduce

1. Navigate to the login page of the application.
2. In the username field, enter the following payload:
```sql
' OR 1=1 --
```
3. Enter any arbitrary value in the password field.
4. Submit the login form.
5. The application authenticates the user as admin due to the injected condition always evaluating to true.
6. Navigate to the admin profile page.
7. Observe that the flag is displayed.