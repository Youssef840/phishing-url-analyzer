# Security Policy

## Reporting a vulnerability
Please **do not** open a public issue for security problems. Use GitHub's
"Report a vulnerability" button (Security tab → Advisories) and include steps to reproduce.

## Design notes
- The analyzer never renders or executes the target page. It only performs DNS, WHOIS,
  a TLS handshake to read the certificate, and optional reputation API lookups.
- TLS connections to private / loopback / link-local addresses are skipped by default
  (`ALLOW_PRIVATE_TARGETS=false`) to reduce SSRF risk when the app is exposed.
- API keys are read from environment variables only; `.env` is git-ignored.
- If you deploy publicly, put it behind a reverse proxy with rate limiting.
