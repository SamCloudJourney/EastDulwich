# EastDulwich Edge Engine — Build Plan & Deep-Research Verdict

> Goal: a legal, UK-operable "probability machine" that finds and exploits mispricing
> in prediction/betting markets. Sub-£1k starting bankroll. Built by Opus 4.8.
> Backed by a 103-agent, adversarially fact-checked deep-research run (June 2026).

---

## ⛔ VERDICT: Polymarket/Kalshi are OFF the table for a UK resident

All findings below verified **high confidence, 3-0** in adversarial review.

- **Polymarket** — own API geoblock docs list `GB | United Kingdom | Blocked`. No UKGC licence.
  VPN bypass violates **ToS §2.1.4**; active VPN-IP blocking + **documented frozen-funds cases**;
  no FSCS cover, no UK dispute body. **Do not attempt.**
- **Kalshi** — opened to ~140 countries (late 2025) but **UK is on the restricted list**
  (Member Agreement §VI). KYC ties accounts to a non-UK residence. Cannot onboard.
- **Plain English:** "not possible to open an account and place a trade in the UK" (Good Money Guide).
- Why: FCA permanent retail **binary-options ban** (since 2 Apr 2019) + UKGC licensing requirement.

### Tax footnote (UK)
- Polymarket is crypto-based → likely **NOT tax-free** (CGT/income on disposals + systematic trading).
- UKGC-regulated exchanges (Matchbook, Smarkets, Betfair) → winnings **exempt from Income Tax & CGT**.
- So the blocked option was also the worse-taxed one.

---

## ✅ THE PIVOT: legal UK venues (ranked by cost)

| Venue | Commission | Notes |
|---|---|---|
| **Matchbook Predictions** ⭐ | 2% | First UKGC-licensed YES/NO **prediction-market** product (launched Jan 2026). Closest legal match to Polymarket/Kalshi. |
| **Smarkets** | 2% | UKGC+MGA, clean API, no winner surcharge. |
| **BETDAQ** | 2% | UKGC exchange (independently owned). |
| **Betfair** | 5% + **Expert Fee up to 40%** above £25k rolling 52-wk profit | Deepest liquidity; surcharge punishes consistent winners — use for liquidity only. |

**Truth anchor:** Pinnacle odds (sharpest book; closing line ≈ true probability).

---

## 🏗️ WHAT GETS BUILT — "EastDulwich Edge Engine"

Modular Python system. Five components:

1. **Data layer** — clients for Matchbook + Smarkets (+ Betfair for liquidity) live order books,
   plus a Pinnacle reference feed. Normalised into one internal price book.
2. **Edge engine** — two strategies side by side:
   - **A. Cross-venue arbitrage** (low risk): back on one venue > lay on another (incl. commission) → locked profit.
   - **B. Pinnacle-anchored value betting** (the real long-term edge): bet when a venue's price beats Pinnacle no-vig fair value by a threshold. "Beat the closing line."
3. **Execution layer** — auto-place via venue APIs. **Starts in alert-only/paper mode.** Hard caps + kill-switch.
4. **Risk & bankroll** — ¼-Kelly staking, exposure caps, full ledger, **CLV (closing-line value) tracking** = the true scoreboard.
5. **Backtest/paper harness** — prove the edge on Manifold (play money) + historical odds before going live.

### The loop
```
every few seconds:
  pull prices  →  Matchbook + Smarkets + Pinnacle
  per market:
    A) cross-venue: back(X) > lay(Y) + commission?  → arb → place both legs
    B) value: venue price > Pinnacle-fair + threshold? → +EV → place, ¼-Kelly
  log everything, track CLV, respect exposure caps
```
Runs 24/7 on a ~£4/mo VPS. Acts only when the maths is favourable.

### Key design constraint
Route value bets through **Matchbook/Smarkets (2%, no surcharge)**; use Betfair only for liquidity/arb legs
to dodge the Expert Fee. Most people miss this and it eats their edge.

---

## 💷 REALISTIC MONEY (honest)

Returns scale with **bankroll**, not cleverness. Sub-£1k is small → percentages of a small number.

| Phase | Bankroll | Realistic net | Notes |
|---|---|---|---|
| Months 1–2 (paper → tiny live) | £500–1k | ~£0 to +£100/mo | Tuning. Treat as tuition. |
| Months 3–6 (dialled in) | £1k growing | £100–300/mo | Arb + value layers contributing. |
| 6–12 months (reinvest) | £2–4k | £300–700/mo | Scales with bank, not effort. |

- Good system ≈ **3–8%/month on turnover**; turnover capped by bank + liquidity + stake limits.
- Value betting is **variance-heavy** — losing weeks even when every bet is +EV. Edge shows over hundreds of bets.
- It's a **compounding machine, not a jackpot.** Legal, tax-free (UKGC venues), runs quietly, grows with the bank.

### Reality check from the research
- Even on Polymarket, only **0.51% of wallets earned >$1,000** (95M txns, Apr 2024–Dec 2025).
- **73% of arb profit** is captured by **sub-100ms bots** — don't compete on latency. Compete on **model quality** (value), not speed.

---

## 🚀 WEEK-1 PLAN

1. Scaffold repo: data clients (Matchbook + Smarkets), price-book, **paper-mode arb detector**.
2. Wire in Pinnacle reference odds.
3. Run **alert-only** 2 weeks on football + horse racing — log every signal + its CLV. No money risked.
4. Read the CLV scoreboard. If we consistently beat the close → turn on small live stakes.

---

*Sources (verified): Polymarket Help Center & API geoblock docs; Kalshi Help Center & Member Agreement;
Good Money Guide; Gizmodo (VPN crackdown); predictmarkets.com; Pinnacle; operator fee pages.
Figures are realistic ranges, not guarantees. Informational use.*
