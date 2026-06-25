# EdgeEngine — Technical Build Reference

> The private sports-betting value/arb engine. Detects mispricing (soft/exchange price vs sharp
> Pinnacle fair price), stakes our own bankroll, logs CLV + P&L. Python, runs 24/7 on a small VPS.
> Paper mode first (zero risk), live stakes only after the edge is proven on closing-line value.

---

## 1. DATA SOURCES (with real access notes)

| Source | Role | Access reality |
|---|---|---|
| **Pinnacle (the "truth")** | Sharp reference price | ⚠️ Pinnacle **closed its public API on 23 Jul 2025.** Get it via third-party: **OddsPapi** (346 books, Pinnacle odds, free historical, real-time WebSockets, no delay) — best for us. Backups: SportsGameOdds, odds-api.io. |
| **Betfair Exchange** | Where we bet (deepest liquidity) | Free API. Need account + **app key** (Delayed key = free 5s-delayed data; Live key = place real bets). Auth = SSL cert + session token. Python: **`betfairlightweight`**. |
| **Smarkets** | Cheaper exchange (2%, no premium charge) | HTTP trading API (market data + orders) but **gated** — must submit API Request Form + get approved. Add in phase 2. |
| **Matchbook/BETDAQ** | Extra exchanges | Optional later for more liquidity/arb legs. |

**MVP data plan:** Pinnacle via **OddsPapi (free tier)** + **Betfair** exchange odds. That's enough to detect and (later) place edges. Smarkets once approved.

---

## 2. THE CORE MATH — devig & +EV

The whole engine hinges on turning Pinnacle's odds into a **fair probability**, then comparing to the exchange.

**Step 1 — Devig Pinnacle.** Remove the margin to recover fair probabilities. Four methods:
- **Multiplicative** (MPTO) — spreads vig proportionally. Default, fine for most 2-way markets.
- **Power** — better for big favourites / 3+ way markets.
- **Shin** — distributes vig toward favourites (insider-risk model); more accurate, more complex.
- **Additive** — splits vig equally; can produce negative probabilities for longshots (avoid for those).
- *Plan: start Multiplicative, add Power/Shin for favourites & multi-way.*

**Step 2 — Fair odds.** `fair_odds = 1 / fair_probability`.

**Step 3 — +EV test.** For exchange/soft decimal odds `o` and fair prob `p`:
`EV = p·(o − 1) − (1 − p)`. Flag when `EV > threshold` (~2%+ to absorb model error).

**Step 4 — Arb test.** Two-way across venues: if `1/o_A + 1/o_B < 1`, lay both sides → locked profit.

**Step 5 — CLV (the scoreboard).** Compare each bet's price to the **no-vig closing line**. Consistently beating it is *the single best predictor of long-term profit* — this is how we validate the engine in paper mode before risking money.

---

## 3. ARCHITECTURE (pipeline)

```
[Ingest]  Pinnacle (OddsPapi) + Betfair odds  ── WebSocket/poll
   ↓
[Normalise]  entity-resolution: match same event+selection across sources  ← the hard part
   ↓
[Devig]  Pinnacle → fair probabilities (multiplicative/power/shin)
   ↓
[Detect]  +EV (EV>threshold) and arbs (sum of inverse odds <1)
   ↓
[Filter]  drop stale odds, palpable errors, dead liquidity, suspended markets
   ↓
[Stake]   ¼-Kelly sized to bankroll, exposure caps
   ↓
[Act]     PAPER MODE: log only   |   LIVE: place via Betfair API
   ↓
[Record]  ledger + CLV + P&L  → file/dashboard we read together
```

**The hard part = normalisation/entity resolution** (matching "Man Utd" vs "Manchester United", market/handicap notations). False matches = phantom edges = wasted/false bets. Core engineering focus.

---

## 4. STACK & OPEN-SOURCE REFERENCES

- **Language:** Python 3.11+
- **Betfair:** `betfairlightweight` (clean API wrapper, handles auth/streaming)
- **Pinnacle data:** OddsPapi SDK / REST + WebSocket
- **Engine:** pandas/numpy for devig + EV; asyncio for real-time
- **Storage:** SQLite (ledger, CLV log) → simple, file-based
- **Reference repos to learn from (not copy):**
  - `betfair-datascientists/API` — Betfair's own examples + Automation Hub tutorials
  - `sferez/Arbitrage_Betting_Bot` — scrapes books, finds arbs, supports Pinnacle
  - `LeartS/betbot` — Python arb bot
  - AgentBets "+EV betting bot" guide — Pinnacle-as-truth architecture

---

## 5. KEY GOTCHAS

- **Pinnacle API is closed** → must go through OddsPapi/SportsGameOdds. (Don't build against Pinnacle directly.)
- **Betfair Live key** needs activation + SSL cert auth — small setup hurdle.
- **Smarkets API is approval-gated** → Betfair first, Smarkets later.
- **Betfair Premium Charge** (up to ~40% on big consistent winners) → route value bets through Smarkets/Matchbook once available; use Betfair for liquidity.
- **Latency:** we're NOT competing on sub-100ms (that's the pros' game). Value betting on slower-moving lines is the playable angle, not millisecond arb.
- **Stake limits / gubbing:** exchanges don't gub like bookies, but liquidity caps size — fine at our bankroll.

---

## 6. PHASED BUILD

- **Phase 0 (now):** scaffold repo, config, SQLite ledger.
- **Phase 1 — paper engine:** OddsPapi (Pinnacle) + Betfair data → devig → +EV/arb detection → **log signals + CLV, bet nothing.** Run ~2 weeks.
- **Phase 2 — validate:** read the CLV scoreboard together. Beating the close? → edge is real.
- **Phase 3 — tiny live:** Betfair Live key, ¼-Kelly micro-stakes, monitor.
- **Phase 4 — scale:** add Smarkets, more sports/markets, better devig (Power/Shin), grow bankroll with profits.

---

*Sources: Betfair Developer docs + Automation Hub; Smarkets docs.smarkets.com; OddsPapi/SportsGameOdds (Pinnacle access post-shutdown); Pinnacle Odds Dropper (devig methods); AgentBets (+EV bot); GitHub (betfairlightweight, sferez, LeartS). Informational; not betting advice.*
