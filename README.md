# CyberPanel XSS to RCE (CVE-2026-XXXXX)

One-click Remote Code Execution in CyberPanel v2.4.3 via unauthenticated API endpoints.

## Overview

This exploit chains multiple vulnerabilities in CyberPanel's AI Scanner feature:

1. **Unauthenticated Database Injection**  `/api/ai-scanner/callback` accepts arbitrary data without authentication
2. **Stored XSS**  Malicious payloads are rendered unsanitized in the admin dashboard
3. **CSRF to RCE**  XSS hijacks admin session to create a malicious cron job

## Affected Versions

- CyberPanel ≤ 2.4.3

# Timeline 

- December 16, 2025 Vulnerabilities reported
- December 17, 2025 Initial response and acknowledgment
- December 17, 2025 Platform vulnerabilities fixed and deployed
- December 19, 2025 CyberPanel fixes committed to repository
- January 1, 2026 User notification campaign initiated
- January 18, 2026 Public disclosure
