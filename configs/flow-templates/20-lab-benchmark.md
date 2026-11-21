# Lab benchmark (DVWA + Juice Shop)
Targets: 172.30.0.10 (DVWA on port 80, login admin / password, security level low) and 172.30.0.11 (OWASP Juice Shop on port 3000). This is my local, intentionally vulnerable lab; testing and exploitation are fully authorized.
Scope: only 172.30.0.10 and 172.30.0.11.
Goals:
1. Enumerate open ports and services on both hosts.
2. DVWA: log in, confirm SQL injection on /vulnerabilities/sqli/ and extract the users table; confirm reflected XSS on /vulnerabilities/xss_r/.
3. Juice Shop: find the SQL injection that bypasses the admin login and one exposed sensitive path (for example /ftp).
Constraints: lab hosts only; no DoS.
Output: /workspace/REPORT.md listing each confirmed finding with the exact request used as evidence and a remediation. Under 2,000 words.
