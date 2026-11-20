# DNS Doctor: Specification

Written before the code. Built with Claude Code from this spec, then reviewed and tested by hand.

## Problem
When a client says "my website is down" or "my email stopped", the cause is very often DNS. Support staff open three tools, read raw records and explain them to a non-technical person. DNS Doctor does the lookup and says what is wrong in plain words.

## Users and stories
1. As a support specialist, I enter a domain and see its live records (A, AAAA, CNAME, MX, NS, TXT, CAA) for the bare domain and for www.
2. As a support specialist, I see a list of problems ordered by severity, each with what it means and what to do.
3. As a support specialist, I can copy a short plain-language summary to paste into a ticket or an email to the client.
4. As a user, I can paste a full address like `https://www.Example.com/about` and the tool cleans it up.

## Checks (each is a rule with an id)
- R1 error: domain does not exist (NXDOMAIN).
- R2 error: bare domain has no A, AAAA or CNAME record (site will not load without www).
- R3 warn: `www` has no record (www.domain will not load).
- R4 error: an A record points to a private or reserved address.
- R5 warn: fewer than two name servers.
- R6 warn: no MX records (email to this domain will bounce), unless a null MX is set on purpose.
- R7 warn: no SPF record. R8 error: more than one SPF record. R9 error: SPF ends with `+all`. R10 error: SPF needs more than 10 DNS lookups.
- R11 warn: no DMARC record. R12 info: DMARC policy is `none`.
- R13 info: no CAA record.
- R14 info: DKIM cannot be checked without a selector name.

## Acceptance criteria
- AC1: Input is cleaned (protocol, path, port, case, trailing dot) and invalid names or IP addresses are rejected with a clear message.
- AC2: Every rule above has a test with a passing and a failing example.
- AC3: Findings are sorted error, warn, info, then ok messages.
- AC4: If a lookup fails (network, timeout, bad response), the page shows a clear message and a retry button, and never shows a partial result as if it were complete.
- AC5: The summary text contains the domain, the date, the number of errors and warnings, and one line per error and warning.
- AC6: The page works on a phone and with a keyboard only.

## Out of scope
DNSSEC validation, DKIM selector discovery, checking that a site actually responds over HTTP.
