# Challenge `Sometimes we are just temporarily blind-v2` writeup

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

1. Use the same boolean-based blind SQL injection technique as in Task 2.1, relying on differences in server responses (Found 4 articles vs Found 0 articles).
2. Enumerate database tables and identify the super_s_sof_secrets table.
3. Extract the table schema and locate the secret column.
4. Perform character-by-character extraction of the secret using SUBSTR, ensuring the comparison preserves case sensitivity.

> **Note:** The exploitation script is identical to Task 2.1. The only required adaptation is ensuring that the character extraction logic includes both uppercase and lowercase characters in the tested character set.

[POC](Sometimes_we_are_just_temporarily_blind.py)