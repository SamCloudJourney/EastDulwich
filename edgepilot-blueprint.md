# EdgePilot — The Complete Project Blueprint

> An AI-native betting-edge copilot for the UK. Finds +EV bets, arbs and matched-betting
> offers across every book — and is the **first tool you can actually talk to about them.**
> "Sell the shovels, not the picks." Legal, tax-free (UK exchanges), uncapped by bankroll.

---

## 💡 THE INSANE INSIGHT (why this wins)

The research found a clean, unfilled gap right down the middle of the market:

- **General AI (ChatGPT/Claude)** can *talk* about bets but has **no real-time odds** — useless for actual edges.
- **Specialist tools (OddsJam, RebelBetting, BetBurger)** have real-time odds but **can't hold a conversation** — you literally can't ask OddsJam *"why is this +EV?"* or *"is this arb safe?"*

**Nobody has combined real-time odds data + conversational AI.** That's the whole opportunity. EdgePilot is the first **AI-native edge copilot**: it surfaces the opportunities like a scanner, *and* you can ask it "why is this a value bet?", "what's the risk here?", "build me a £500 bankroll strategy." Decision-support, not autopilot — which is exactly what bettors say they want.

This is *uniquely* buildable by a frontier-AI builder. A non-coder can't make it; legacy incumbents would have to rebuild from scratch.

---

## 📊 MARKET & TAM

- UK online sports betting: **£16.8bn annual GGY**, ~**17.4M active bettors**, growing to **15.3M+ online users by 2029** (11–13% CAGR).
- The *tools* sub-market is already proven: **OddsMonkey alone has 450k+ members**, RebelBetting 325k+. Hundreds of thousands of UK users already *pay* for betting tools.
- Capturing even **0.1% of that paying base at £20/mo ≈ £100k+/yr**; 1% is a £1m+ business.

---

## 🏟️ COMPETITOR MATRIX (with real pricing)

| Competitor | What | Price/mo | Weakness we exploit |
|---|---|---|---|
| **OddsMonkey** | Matched betting leader (450k+) | £39.99 / £49.99 / **£149 (EV)** | Buggy, bad mobile, "stripped" rewrite, expensive, same owner as Outplayed |
| **Outplayed** | Matched betting (ex-PA) | £39.99 / £49.99 | Same owner as OddsMonkey → complacent |
| **RebelBetting** | Value + arb (325k+) | **£62 / £118** | Hard to navigate, English-only, "guarantee trap" |
| **OddsJam** | US value/arb | **$199–$999** | 2.9★, terrible support, billing tricks, US-focused |
| **Bet Hero** | Value + arb (modern) | €29.99 / €59.99 / €89.99 | Strongest tech rival — watch closely |
| **BetBurger** | Arb-first | £29.99 / £79.99 / £279.99 | Arb-only, dated UX |

**Take:** ~5 real rivals. None are AI-conversational, none are UK-first + all-in-one + honest-billing, most are pricey and clunky.

---

## 🎯 THE GAPS → OUR WEDGES

From real user complaints (Reddit/Trustpilot):
1. **No conversational AI** — can't ask *why*. ← our flagship feature, nobody has it.
2. **Bad mobile / clunky UX** — universal complaint. ← mobile-first, clean.
3. **Billing distrust** — hidden fees, charged-after-cancel (#1 complaint everywhere). ← radical transparency, cancel anytime.
4. **Overpriced** — £60–£800/mo. ← undercut hard.
5. **Fragmented** — separate tools for value / arb / matched betting. ← all-in-one.
6. **Weak automation & alerts** — manual, slow. ← real-time push alerts, smart filters.
7. **Shallow analytics** — ← proper profit + CLV (closing-line value) dashboard = trust as a feature.

---

## 🛠️ THE PRODUCT

**Core engine:** ingest live odds across UK bookmakers + exchanges (Smarkets/Betfair) + a **sharp reference (Pinnacle)**; detect **value bets** (price beats sharp fair value), **arbs** (locked profit), and **matched-betting offers**.

**The AI layer (the moat):**
- "**Explain this bet**" — ask why any signal is +EV, in plain English.
- "**Is this safe?**" — risk check (liquidity, gubbing risk, resolution).
- "**Build my strategy**" — bankroll-aware staking plan (¼-Kelly), tailored to the user.
- "**Coach me**" — onboarding for beginners (huge: converts non-experts the incumbents ignore).

**Trust features:** transparent £ pricing, cancel-anytime, public verified CLV track record.

**Form factors (in build order):**
1. **Discord bot** (launch) — pushes live edges into betting Discords; Whop handles payments/access. Cheapest, fastest, communities already exist.
2. **Web app** — full dashboard + AI chat.
3. **Mobile app** — the thing every incumbent fails at.

---

## 💷 PRICING STRATEGY

Undercut the incumbents, monetise the AI as the premium.

| Tier | Price | What |
|---|---|---|
| **Free** | £0 | Delayed/limited signals + 5 AI questions/day. The hook + lead magnet. |
| **Pro** | **£19/mo** | Real-time value + arb + matched betting, unlimited AI chat, tracker/CLV. Undercuts everyone. |
| **Sharp** | **£39/mo** | Live in-play edges, advanced filters, API/Discord alerts, priority data. |

Anchor: cheaper than RebelBetting's *starter* (£62) while doing *more*. Annual plans at ~30% off for cash-flow + retention.

---

## 🔌 TECH & DATA (the critical dependency)

The whole product rides on an **odds feed that includes a sharp book (Pinnacle)** — that's what makes +EV detection possible. Options researched:

| Provider | Price | Sharps (Pinnacle)? | Verdict |
|---|---|---|---|
| **OddsPapi** | per-request, **free tier** | ✅ 350+ books incl. sharps | **Best for MVP** — dev-first, cheap, has Pinnacle |
| **SportsGameOdds** | $99–499, free tier | ✅ 80+ incl. Pinnacle | Strong backup |
| The Odds API | $30–249 | ❌ no sharps | Cheap but no Pinnacle = weak for +EV |
| OpticOdds | ~$5,000/sport | ✅ enterprise | Too expensive |

**Stack:** Python/Node backend, odds via OddsPapi, edge-detection engine, Claude API for the AI layer, web dashboard, Discord bot. Runs cheaply on a small VPS — total infra **<£100/mo** at MVP.

---

## 🚀 GO-TO-MARKET

Researched channels, in priority order:
1. **Discord-first launch** — betting Discords are huge; a bot that pushes live edges is "a service worth paying for." Whop handles payments. Fastest 0→first-revenue with near-zero CAC.
2. **SEO + comparison content** — 78% of betting affiliates rely on SEO; review/comparison pages are the dominant organic channel. Build "best value betting tool UK" content, win the long tail. (6–12 month compounding play.)
3. **Affiliate/referral** — bettors refer bettors; rev-share program.
4. **YouTube/influencer** — sponsor matched-betting/value creators (Caan Berry-type audiences).
5. **Poach the disgruntled** — target OddsMonkey/OddsJam refugees directly (Reddit, Trustpilot, comparison keywords).

---

## 📈 FINANCIAL SHAPE (honest)

- **Costs:** ~£100/mo infra + data at MVP. Solo-built (you + AI) → no salaries.
- **Path:** Discord bot → first £1–3k MRR in months on near-zero CAC → web/mobile + SEO → **£5–30k MRR in 12–24 months** (in line with comparable solo betting-SaaS). Ceiling ~£100k MRR before saturation.
- **Why it's a real business:** recurring, scales with subscribers (not bankroll/liquidity), legal, tax-clean for users on exchanges.

---

## 🗺️ ROADMAP

- **Week 1–2:** odds feed wired (OddsPapi) + value/arb detection engine + a working **Discord bot** pushing real signals. Validate edges are real.
- **Week 3–4:** add the **AI "explain this bet" layer** (the differentiator) + CLV tracker.
- **Month 2:** web dashboard + free/Pro tiers + Stripe. Soft-launch in 2–3 Discords.
- **Month 3+:** matched-betting module, SEO content engine, mobile app, affiliate program.

---

## ⚠️ HONEST RISKS

- **Bet Hero** is a capable modern rival — we differentiate on AI-chat + UK-first + honesty, not just features.
- **The edge must be real** — value detection lives or dies on the Pinnacle-anchored model; CLV tracking keeps us honest and is the trust proof.
- **Data cost scales with usage** — manage via caching + tiered limits.
- **Affiliate/review SEO is pay-to-play** — our honest, public track record is the counter-brand.
- **Gambling-adjacent marketing rules** — stay tool/education-focused (we sell software, not bets), which also keeps us clear of operator licensing.

---

## ✅ THE ONE-LINER

> **EdgePilot — the first betting-edge tool you can talk to.** Finds value bets, arbs and matched-betting offers across every UK book, explains *why* each one's an edge, and builds you a plan — honest pricing, mobile-first, no tipster nonsense. The AI-native scanner the legacy tools can't rebuild fast enough.

---

*Sources: Statista/Grand View (market); OddsMonkey, Outplayed, RebelBetting, OddsJam, Bet Hero, BetBurger pricing pages & reviews; OddsPapi, SportsGameOdds, The Odds API (data); Trustpilot & Reddit (complaints/gaps); Parlay Savant, OddsJam (AI-gap analysis); Business of Apps, StatsDrone (acquisition channels). Figures are reported ranges. Informational use.*
