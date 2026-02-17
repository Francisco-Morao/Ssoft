# Challenge `Wow, it can't be more juicy than this!` writeup

- Vulnerability: What type of vulnerability is being exploited
  - SQL Injection, specifically UNION-based SQL Injection
- Where: Where is the vulnerability present
  - In the Blog search input field. User input is directly concatenated into an SQL SELECT query without proper sanitization or parameterization.
- Impact: What results of exploiting this vulnerability
  - Enumerate database metadata via the sqlite_master table
  - Discover hidden or unpublished tables
  - Access unreleased or confidential blog posts
  - Read sensitive content intended to remain private which leads to information disclosure and complete loss of confidentiality for hidden data.

## Steps to reproduce

1. In the blog search input field, test for SQL injection by inserting the following payload:
```sql
' UNION SELECT
```
An SQL error message is returned.

2. From the error message, it is possible to infer that the vulnerable query selects three columns and that there is a table named blog_post with the columns:
```sql
id, title, content
```
Therefore, all injected UNION SELECT statements must include three arguments.

3. Inject the following payload to enumerate the database table names using SQLite’s metadata table:
```sql
' UNION SELECT tbl_name, tbl_name, tbl_name FROM sqlite_master --
```
4. Observe that the application returns multiple table names, including a hidden table named: `secret_blog_post`
5. Use the discovered table name to extract its contents by injecting the following payload:
```sql
' UNION SELECT id, title, content FROM secret_blog_post --
```
6. Observe that a secret, unreleased blog post is displayed, revealing the flag.