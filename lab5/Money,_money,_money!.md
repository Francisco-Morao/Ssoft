# Challenge `Money, money, money!` writeup

- Vulnerability: What type of vulnerability is being exploited
  - SQL Injection, specifically Stored SQL Injection via Profile Update
- Where: Where is the vulnerability present
  - User profile page (profile update functionality), where logged-in users can update their profile information. User input is directly inserted into an SQL UPDATE statement without proper validation or parameterization.
- Impact: What results of exploiting this vulnerability
  - Modify normally read-only fields
  - Arbitrarily increase their token balance
  - Reach the required number of tokens to obtain the lottery jackpot
  - Gain unauthorized rewards
  - In general it breaks the integrity of the system and enables privilege and value escalation.

## Steps to reproduce

1. Register a new user account using any username and a non-meaningful password, as instructed.
2. Log in with the created account.
3. Navigate to the user profile page.
4. In one of the editable profile fields, insert the following SQL injection payload:
```sql
', tokens='95171
```
(Note: the token value is unique per user and changes for each player.)

5. Submit the profile update form to obtain the jackpot.
6. Observe that the number of tokens has been modified, even though it should be read-only and the flag is displayed.