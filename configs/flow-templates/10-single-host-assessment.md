# Single-host authorized assessment
Target: <TARGET_IP> (<WHAT IT IS>; I own it and this test is authorized).
Scope: this single IP only. Do not scan any other host or subnet. Network egress from the tool container is restricted to in-scope addresses, so do not try to install packages; use the tools already in the image.
Goals:
1. TCP scan of the top 1000 ports, then service/version detection on open ports.
2. UDP check of 53, 67, 123, 161, 500, 1900, 5353.
3. For each web service: identify the application and version, review security headers and TLS configuration, check a short list of default credentials, and run nikto.
4. Research known CVEs for the identified versions. Cite only CVE IDs you can attribute to the exact vendor and product; if you cannot verify an ID, write "no CVE ID verified" instead of guessing.
Constraints: no DoS, no brute forcing beyond a short default-credential list, and stop and report before any exploitation.
Output: write /workspace/REPORT.md section by section (executive summary; findings table with severity, evidence, remediation; CVE table; evidence index). Keep it under 3,000 words.
