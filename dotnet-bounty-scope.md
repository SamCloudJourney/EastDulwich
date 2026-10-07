# Microsoft .NET Bug Bounty — Scope & Rules

> Program page: https://www.microsoft.com/en-us/msrc/bounty-dot-net-core
> Submit via: MSRC Researcher Portal (https://msrc.microsoft.com)

---

## Rewards

| Impact | Max Payout |
|---|---|
| Critical RCE or Elevation of Privilege | $40,000 |
| Critical Security Feature Bypass | $30,000 |
| Critical Remote Denial of Service | $20,000 |
| Spoofing / Tampering / Info Disclosure / Insecure Docs | $20,000 |
| Floor (minimum qualifying submission) | $1,250 |

**Only Critical or Important severity vulnerabilities qualify for bounty.**

Reports are graded "complete" (working exploit) or "not complete" (theoretical).
Complete reports with functional PoC get top-tier payouts.

---

## In Scope

- All **supported versions** of .NET and ASP.NET Core
- **Blazor** and **Aspire** (part of ASP.NET Core)
- **F#** and adjacent .NET technologies
- Supported **ASP.NET Core on .NET Framework** versions
- **Templates** shipped with .NET / ASP.NET Core
- **GitHub Actions** in dotnet/aspnetcore and dotnet/runtime repos
- **Release candidates** for upcoming .NET versions
- **Preview Features** listed on dotnet GitHub
- **Documentation** on learn.microsoft.com/dotnet/ and associated samples

---

## Out of Scope — Do Not Submit

- Already **publicly disclosed** vulnerabilities
- Vulns in **user-generated content**
- Vulns requiring **extensive or unlikely user interaction**
- Vulns that only work when **built-in mitigations are disabled**
- **Low-impact CSRF**
- **Low-impact server-side information disclosure**
- **Platform-level** issues not specific to .NET (IIS, OpenSSL, Kestrel's OS layer, etc.)
- Anything below Important severity

---

## Submission Requirements

1. **Coordinated Vulnerability Disclosure (CVD)** — mandatory. Public disclosure before Microsoft's fix = disqualification.
2. Submit through the **MSRC Researcher Portal** — not email, not GitHub issues.
3. Include in every report:
   - Bounty program name: ".NET Bounty Program"
   - Exact product/framework **version numbers** tested
   - **Step-by-step repro** on a fresh install
   - **PoC or exploit code** (functional = "complete" = higher payout)
   - **Impact statement** — what an attacker gains, blast radius
   - **Vulnerability type** (RCE, deserialization, SSRF, etc.)

---

## Report Quality Tiers

| Tier | What It Means | Effect on Payout |
|---|---|---|
| High | Clear writeup + working exploit + impact analysis | Maximum award range |
| Medium | Repro steps + partial PoC, some gaps | Mid-range award |
| Low | Theoretical or incomplete, missing repro | Minimum or no award |

---

## Key Dates & Notes

- Program updated **July 2025** with increased rewards (max raised to $40K).
- Scope expanded to include GitHub Actions, F#, and docs.
- Microsoft's "In Scope by Default" policy now covers third-party code shipped inside .NET.
