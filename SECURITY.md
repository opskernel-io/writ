# Security policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.x     | Yes       |

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities by email to **thewismit@gmail.com**. Include:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- Affected versions (if known)

You will receive an acknowledgement within 2 business days. We aim to release a fix within 30 days of confirmation; for critical issues, sooner.

**Disclosure window:** We follow a 90-day coordinated disclosure policy. After 90 days from the date of your report (or on the day a fix ships, whichever comes first), you are free to publish your findings. We will credit you in the release notes unless you prefer to remain anonymous.

## Scope

In scope: the `writ` Go module and the `cmd/writ` CLI.

Out of scope: vulnerabilities in third-party dependencies (report those to the respective projects). We will bump affected dependencies promptly when upstream fixes ship.
