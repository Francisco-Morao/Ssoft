Everthing about the course of Software Engineering.

### The project
You can find the project with its documentation in the `project` folder. The project is a static analysis tool that uses taint and sanitization analysis to detect data flow vulnerabilities (like SQL injection and XSS) in Python web applications. The tool is built using the `ast` module to parse Python code and analyze the data flow from sources (user input) to sinks (vulnerable functions) while considering sanitization functions that can mitigate vulnerabilities.

### The labs
You can also find the labs in the `labs` folder. The labs cover various security vulnerabilities and exploitation techniques, including web security (XSS, SQL injection), binary exploitation (buffer overflows, return-oriented programming), and secure coding practices.

The labs cover:

- Lab 2: Binary search attacks, Python sockets, web requests, secure design principles
- Lab 3: Race conditions, serialization attacks (pickle)
- Lab 4: XSS (Cross-Site Scripting), cookie manipulation, WAF bypass
- Lab 5: More web security vulnerabilities
- Lab 6-7: Buffer overflows, return address manipulation, memory exploits