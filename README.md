# DNS Doctor

Type a domain and get its live DNS records plus a plain-words list of what is wrong and how to fix it. Built from a problem I deal with in web support: a client says "my site is down" or "my email stopped", and the cause is usually DNS.

**Live demo:** https://dns-doctor-shafi.netlify.app

Personal project, built with Claude Code from a written spec ([SPEC.md](SPEC.md)) and reviewed by hand.

## What it checks
14 rules, each with a plain explanation and a fix:
- **Website:** domain does not exist, bare domain has no address, `www` missing, A record pointing to a private address.
- **Name servers:** fewer than two.
- **Email:** no MX, no SPF, two SPF records, SPF ending in `+all`, SPF over the 10-lookup limit, no DMARC, DMARC in monitor-only mode.
- **Notes:** no CAA record, DKIM not checked (it needs a selector name).

"Copy summary for a ticket" gives a short text with the domain, date, counts and one line per problem, ready to paste into a ticket or a client email.

## How it works
- **Live data, no backend:** the browser asks Cloudflare's public DNS-over-HTTPS service directly. Nothing is stored.
- **Pure analysis:** `analyze()` takes the records and returns findings, so every rule is a plain function with tests.
- **All or nothing:** if any single lookup fails, the page shows an error with a Retry button instead of a half-finished result.
- **Input cleanup:** paste `https://WWW.Example.com:8080/about` and it checks `example.com`; IP addresses and invalid names get a clear message.
- **Accessibility:** labelled input, live status region, keyboard-only use, dark mode.

## Tests
29 tests (Vitest and React Testing Library) cover input cleanup, every rule with passing and failing examples, ordering, the summary text, the lookup layer (timeouts, HTTP errors, bad bodies) and the page itself. They run in GitHub Actions.

```bash
npm install
npm run dev
npm test
npm run build
```

## Limits
It does not validate DNSSEC, discover DKIM selectors or check that the website actually responds. DNS answers come from one public resolver and can differ from what a visitor's own resolver caches.
