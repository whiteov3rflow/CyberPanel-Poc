# CyberPanel XSS to RCE (CVE-2026-XXXXX)

One-click Remote Code Execution in CyberPanel v2.4.3 via unauthenticated API endpoints.

## Overview

This exploit chains multiple vulnerabilities in CyberPanel's AI Scanner feature:

1. **Unauthenticated Database Injection** — `/api/ai-scanner/callback` accepts arbitrary data without authentication
2. **Stored XSS** — Malicious payloads are rendered unsanitized in the admin dashboard
3. **CSRF to RCE** — XSS hijacks admin session to create a malicious cron job

## Affected Versions

- CyberPanel ≤ 2.4.3
