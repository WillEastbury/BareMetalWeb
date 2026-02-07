The results of our OWASP scan show that we have no critical or high vulnerabilities, and only a few medium and low vulnerabilities that are mostly informational or best practice recommendations. This is a great result and shows that our code is generally secure and follows good practices.

Here is the detailed report:
A01:2025 Broken Access Control - all scanned control features fixed, CSRF and XSS protections enabled as is CORS support.  
A02:2025 Security Misconfiguration - 
A03:2025 Software Supply Chain Failures - WE USE ONLY Asp.net core and kestrel, no other dependencies, and we build everything else from scratch, so no supply chain risks.
A04:2025 Cryptographic Failures - 