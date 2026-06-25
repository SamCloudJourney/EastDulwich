# Probability Machines — Money-Making Options (Research Notes)

> Goal: build a "probability machine" that makes money — quantified edges, **not** financial-markets trading.
> Split everything into two kinds of money:
> - **Path A — run it privately:** you risk capital, the machine finds the edge. (The secret one.)
> - **Path B — sell the machine:** you never bet; you rent the tool to people who do. (The businesses.)

---

## ⭐ THE SECRET ONE — run privately, makes the money

### Prediction-Market Edge Engine (Polymarket / Kalshi)

The single best fit. A bot that finds and exploits mispricings in prediction markets.

**Why it wins**
- Genuine, documented edges (not hype).
- ~$10B+ traded **per month** across Kalshi + Polymarket — young, inefficient markets.
- API-first, open-source SDK exists.
- **The venue does not ban you for winning** (unlike bookmakers, who gub/limit winners). This is the killer advantage — you can run it quietly, indefinitely.
- Low capital to start: hundreds of $/£ + a ~$5/mo VPS.

**The three real edges**
1. **Cross-platform arbitrage** — same event priced 2–5% apart on Kalshi vs Polymarket. Buy cheap side, sell rich side. Windows are *seconds* → it's a latency game.
2. **Intra-market arbitrage** — when YES + NO shares don't sum to $1.00, buy the underpriced side. Mechanical.
3. **Lag / information edge** — e.g. Polymarket's 5-min BTC up/down markets trail Binance's price by 30–90 seconds. Model true probability, bet the gap.

**Hard truths**
- Edge is **small per trade (1–5%)** — money comes from volume × discipline × bankroll, not big single "insane" bets. The "insane" part is the systematization.
- Infrastructure matters more than cleverness: server location/latency (Amsterdam ~5ms to London vs US-East ~130ms), WebSocket feeds not REST polling.
- Start small, prove the edge on a live ledger before scaling size.

**Stack (starting point)**
- Python + asyncio
- Polymarket open-source SDK (`py-clob-client`), Kalshi API
- Binance WebSocket (for lag plays)
- VPS near the venue (~$5/mo)
- CLOB WebSocket feed: `wss://ws-subscriptions-clob.polymarket.com/ws/`

**Upgrade path:** add **market-making** (quote both sides, capture 2–8¢ spread, stay outcome-neutral; Polymarket charges **zero maker fees**).

---

## 💼 THE BUSINESSES — build the machine, sell access

### Business Idea #1 — Odds/Value Scanner SaaS ("sell the shovels")
- You never gamble. Build software that scans for value bets / arbs / line moves and charge a subscription.
- **Highest durable ceiling on the whole list:** realistically $5–30k MRR in 12–24 months for one technical founder; ~$100k MRR ceiling before copycats.
- No bookmaker can ban you; no variance.
- Best move: run the secret engine (above) for yourself, then productize it as this.

### Business Idea #2 — AI Prediction-Model SaaS / Data Service
- Sell AI-generated predictions / win-probability reports as a subscription.
- **No bookmaking licence needed** — pure data product, legal + scalable.
- Real example: *Footy Amigo*, ~£25/mo × ~100 subs = ~£30k/yr (~$37k) from one founder.
- AI betting-analytics market projected ~$1.7B (2025) → ~$8.5B (2033).

### Business Idea #3 — Picks/Signals subscription (built on a real edge)
- Publish a verifiable track record (6–12 months), then convert to paid tier.
- Highest margin at scale, you own the audience — but needs a public, trusted record first.

---

## 📊 FULL RANKED LIST (all 13 options researched)

Scored on: Edge real? · Buildable? · Durable (survives bans/patches)? · Ceiling · Capital.

### TIER S — build these
1. **Prediction-market edge engine (Polymarket/Kalshi)** — real ✅ · buildable ✅✅ · durable ✅ · ceiling high · capital low. *THE secret one.*
2. **Odds/value scanner SaaS** — business not a bet · highest durable ceiling · capital low.
3. **AI prediction-model SaaS** — no licence needed · scalable · capital low.

### TIER A — real edges, but capped or grindy
4. **Positive-EV value sports betting** — strongest *proven* math edge, BUT books ban winners. Best as the engine behind #2/#3.
5. **Prediction-market market-making** — capture 2–8¢ spreads, outcome-neutral, zero maker fees on Polymarket. Natural upgrade to #1.
6. **Lottery roll-down +EV exploit** — mathematically guaranteed when it appears (Selbee group netted $7.75M; MIT group $3.5M on Cash WinFall). Rare windows, needs $100k+/draw + physical logistics. Watch for it.

### TIER B — works, low ceiling / high friction
7. **Matched / bonus-arbitrage betting** — near-zero risk, £300–1k/mo, capped by gubbing. Good *starter capital* to fund Tier S.
8. **Sweepstakes-casino promo arbitrage (US)** — structured promo extraction, soft lines on new books. Grindy, geo-limited.
9. **DFS solvers (lineup optimizers)** — real edge vs soft opponents, but crowded tool market, grindy.
10. **Betfair exchange scalping** — £200–500/mo on £3k bank (top traders £5–8k/mo) but 6–8 hrs/day screen-watching + premium charges. A job, not a machine. Borderline "trading."

### TIER C — avoid
11. **Crypto airdrop farming** — $600–35k per *good* project, but 88% of tokens die in 3 months; 85% of drops now filter sybils with AI. Easy era over.
12. **Casino advantage play (counting/hole-carding/edge-sorting)** — real edges but you get backed off/banned; CSMs killed shuffle tracking; doesn't scale into a machine.
13. **Online poker bots** — banned on every major site, legally dicey, market full of scam bots (−87bb/100). Hard pass.

---

## ✅ THE VERDICT / PLAN

**Build #1 (run privately) → wrap it as #2 (sell publicly).**
- Secret engine makes money quietly on a venue that won't ban you.
- The SaaS layer is bigger and more durable than the betting itself.
- Optionally fund the build with a bit of matched betting (#7) for zero-risk starting capital.

**Next step:** spec the #1 build — concrete architecture, data sources, and a week-1 starting point.

---

*Research notes compiled from public sources (QuantPedia, NPR, chudi.dev, Polymarket SDK, Pinnacle, OddsPapi, Footy Amigo case study, CBS 60 Minutes, Caan Berry, advantage-play & airdrop guides). Edges and figures are reported ranges, not guarantees. For informational use.*
