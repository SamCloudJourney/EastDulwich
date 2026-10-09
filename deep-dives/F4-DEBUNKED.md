# F4 STATUS: DEBUNKED -- Do Not Submit

## Original Claim
Kestrel's bare LF acceptance in HTTP headers creates a parsing differential with "CRLF-strict" proxies (nginx, HAProxy), enabling request smuggling.

## Why It's Wrong

### Empirical Test: nginx 1.24.0
**Sent to nginx:**
```
X-Custom: innocent\nEvil-Header: injected\r\n
```
(One header with bare LF embedded in value)

**What nginx forwarded to backend:**
```
Line 3: X-Custom: innocent\r\n     (CRLF normalized)
Line 4: Evil-Header: injected\r\n  (CRLF normalized, as SEPARATE header)
```

**Result:** nginx SPLIT at the bare `\n`, treating it as a header line terminator. It forwarded TWO separate headers with proper CRLF. **No bare LF reached the backend.** No parsing differential exists.

### Smuggling attempt:
```
X-Custom: value\nGET /smuggled HTTP/1.1\nHost: evil\n\r\n
```
**nginx response: 400 Bad Request** -- nginx split at `\n`, saw `GET /smuggled...` as an invalid header line, and rejected the request.

### Research Confirmation
- **nginx core developer (Maxim Dounin):** "nginx accepts both standard CR LF and bare LF"
- **HAProxy author (Willy Tarreau):** "I have always been tolerant for bare LFs in headers and trailers"
- Both proxies are LF-TOLERANT, not CRLF-strict
- Both reconstruct headers from parsed state when reverse-proxying

### The Proxy Behavior Matrix Was Wrong

| Proxy | F4 Claimed | Reality |
|-------|-----------|---------|
| nginx | CRLF-strict, forwards bare LF as data | LF-tolerant, splits at bare LF |
| HAProxy | CRLF-strict, forwards bare LF as data | LF-tolerant, splits at bare LF |

Since both proxies AND Kestrel all treat bare `\n` as a line terminator in headers, there is NO parsing differential and NO smuggling vector.

### CVE-2025-55315 Distinction
That CVE was about **chunk extension** parsing, not header parsing. Different parser, different behavior, different attack surface. The F4 submission incorrectly extrapolated from chunk extensions to headers.
