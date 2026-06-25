# EdgePilot — Project Blueprint (Agreed v2)

> A design-led, mobile-first **PWA** that detects betting-market mispricing (value bets, arbs,
> matched-betting offers) across UK books + exchanges and pushes them to the user in real time.
> We sell the *detection tool*, never picks. Legal, tax-free for users on exchanges, uncapped by bankroll.
> No conversational AI. Native iOS/Android apps are Phase 2 (billed via web to avoid Apple's cut).

---

## 1. THESIS (why this makes money)

Betting markets are *mostly* efficient but not perfectly so. Sharp books (Pinnacle) price events near
true probability; soft books and exchanges lag. The gap between "true price" and "offered price" is a
**measurable, exploitable edge**. Detecting that gap at scale is a data/engineering problem — which is
exactly the kind of problem a frontier-AI builder can solve cheaply and a non-coder cannot.

**Key strategic move:** we don't bet (bankroll-/liquidity-capped, variance-heavy). We **sell the
detection** as software — recurring revenue, no variance, scales with subscribers. And we sell *tools*
not *picks*, because concentrated picks decay as followers pile in, whereas a scanner surfacing thousands
of diffuse opportunities does not.

---

## 2. THE EDGE, FORMALLY

**Value (+EV):** strip the margin ("vig") from the sharp book to get fair probability `p`. If a soft
book/exchange offers decimal odds `o` with `o > 1/p`, the bet has positive expected value:
`EV = p·(o−1) − (1−p)`. We surface every selection where `EV` exceeds a threshold (≈2%+ to absorb model error).

**Arbitrage:** for a two-way market, if `1/o_A + 1/o_B < 1` across two venues, backing both sides locks a
guaranteed profit regardless of outcome. Mechanical, near-zero risk.

**Matched betting:** extract bookmaker sign-up/reload offers by backing at the bookie and laying on an
exchange — near risk-free, the beginner on-ramp.

**The truth metric — CLV:** Closing-Line Value measures whether a bet beat the sharp closing price. It's
the only honest, variance-free proof the edge is real, and it becomes our public trust signal.

---

## 3. THE PRODUCT (design-led, mobile-first PWA)

- **Form:** installable PWA — home-screen icon, web push notifications, app-like feel — on **iOS and
  Android** at once, full margins (~3% Stripe vs Apple's 15–30%), instant iteration, no gatekeeper.
- **Hero feature:** **real-time push alerts** ("+EV bet found: 4.2% edge"). Edges are time-sensitive;
  speed of delivery to the phone is the product.
- **Core screens:** live edge feed (value/arb/matched in one place), filters (sport/book/edge size),
  one-tap bet tracker, CLV/profit dashboard.
- **Differentiator = craft:** every incumbent is dinged for clunky, buggy, ugly, bad-on-mobile UX.
  We win on speed, clarity, and beauty. Design is the front door.
- **Trust as a feature:** transparent £ pricing, cancel-anytime, public verified CLV record.

---

## 4. SYSTEM ARCHITECTURE

1. **Ingestion:** poll/stream odds via **OddsPapi** (free tier, 350+ books incl. sharp Pinnacle) or
   SportsGameOdds (backup). A sharp reference is non-negotiable — it's the source of "true price."
2. **Normalisation / entity resolution (the hard part):** match the same event + selection across books
   that name things differently. This matching layer is the real engineering moat.
3. **Edge-detection engine:** compute no-vig fair prices, scan for +EV / arb / matched opportunities,
   filter false positives (stale odds, palpable errors, dead liquidity).
4. **Real-time push pipeline:** fan detected edges to subscribed users by their filters, in seconds.
5. **Frontend:** mobile-first PWA (React/Next.js + service worker for push), Stripe billing.
6. **Infra:** small VPS; total cost **<£100/mo** at MVP. Caching to control data spend.

---

## 5. UNIT ECONOMICS

- **Cost:** ~£100/mo infra+data at MVP; solo-built (you + AI), no salaries.
- **Price:** Free (delayed/limited — the hook) → **Pro £19/mo** → **Sharp £39/mo** (live in-play, advanced filters, priority alerts).
- **Margin:** ~97% on web billing. Data cost is the variable; managed via caching + tiered limits.
- **Trajectory:** £1–3k MRR in months (Discord/PWA, near-zero CAC) → **£5–30k MRR in 12–24 months** →
  ceiling ~£100k MRR. Recurring, scales with subscribers, not bankroll.

---

## 6. COMPETITIVE POSITION

Real rivals (~5): OddsMonkey/Outplayed (£40–149, matched betting, buggy, same owner), RebelBetting
(£62–118, hard UX), OddsJam ($199–999, 2.9★, US-focused), Bet Hero (€30–90, modern — the one to watch),
BetBurger (£30–280, arb-only). **None are UK-first + all-in-one + design-led + honest-billing at £19.**
Incumbents struggle to respond: legacy stacks, revenue dependent on the billing tricks we attack.

---

## 7. GO-TO-MARKET

1. **Discord-first** — push edges into betting Discords (Whop handles payments). First revenue in weeks, ~£0 CAC.
2. **SEO / comparison content** — 78% of betting affiliates rely on SEO; own "best value betting tool UK". 6–12mo compounding.
3. **Affiliate/referral** — bettors refer bettors.
4. **Poach the disgruntled** — OddsJam/OddsMonkey refugees via Reddit, Trustpilot, comparison keywords.

---

## 8. ROADMAP

- **Wk 1–2:** odds feed + edge-detection engine + Discord bot pushing real signals (validate edges).
- **Wk 3–4:** PWA shell, live edge feed, push notifications, CLV tracker.
- **Mth 2:** filters, bet tracker, Free/Pro tiers + Stripe, soft-launch in 2–3 Discords.
- **Mth 3+:** matched-betting module, SEO engine, referral program.
- **Phase 2:** native iOS + Android apps (subscriptions billed on web to dodge Apple's cut).

---

## 9. RISKS

- **Edge realness** — value detection rides on the sharp-anchored model; CLV keeps us honest.
- **Bet Hero** — capable modern rival; differentiate on UK-first + design + honesty.
- **Entity-resolution accuracy** — bad matches = false arbs = lost trust. Core engineering focus.
- **Data cost at scale** — caching + tiering.
- **Stay tool/education-focused** — we sell software, not bets → avoids operator licensing + ad rules.

---

## ONE-LINER
> **EdgePilot — the beautifully designed betting-edge app that finds value bets, arbs and matched-betting
> offers across every UK book and pushes them to your phone in seconds. Honest pricing, mobile-first, no
> tipster nonsense.**

*Sources: competitor pricing pages & Trustpilot; OddsPapi/SportsGameOdds (data); Statista/Grand View
(market); Apple Guideline 5.3 + OddsJam/BettingPros iOS apps (App Store viability). Reported ranges, informational.*
