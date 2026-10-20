# PokéClicker 🎮

A single-page, Pokémon-themed homage to **Cookie Clicker**. Click the big Pokéball to
earn **PokéDollars ($)**, hire automated catchers, evolve your buildings, fill your
PC Box with wild Pokémon, and prestige through the Pokémon League for permanent
income bonuses.

> Fan-made homage. Pokémon © Nintendo / Creatures Inc. / GAME FREAK inc. —
> not affiliated with or endorsed by them. Sprites come from the
> [PokeAPI sprites](https://github.com/PokeAPI/sprites) repository.

---

## Run it

It's a fully static site — no build step.

```bash
# option 1: any static file server
cd pokeclicker
python3 -m http.server 8000
# → http://localhost:8000

# option 2: just open index.html in a browser (works from file:// too,
# as long as you're online for the Tailwind CDN)
```

## Directory layout

```
pokeclicker/
├── index.html                 # single-page app shell (3-column responsive layout)
├── css/
│   └── style.css              # custom animations: popups, toasts, ticker, bob…
├── js/
│   ├── data.js                # game data tables: buildings, items, species, news, achievements
│   └── game.js                # engine: state, economy, rendering, save/load, tick loop
└── assets/sprites/
    ├── items/                 # 11 item sprites (balls, stones, amulet coin…)
    └── pokemon/               # 29 Gen-96px Pokémon sprites (catch pool + building icons)
```

## How to play

- **Click the Pokéball** — earns PokéDollars. 4% of clicks are **CRITICAL ×7**.
- **Every 100 manual clicks a wild Pokémon is caught** (weighted rarity: common →
  legendary) and stored in your **PC Box**, with a cash bonus equal to 30 s of
  production (min $25).
- **Buy buildings** in the Poké Mart (right column). Cost scales:
  `cost(n) = ceil(baseCost × 1.15 ^ owned)`.

  | Building          | Cost      | $/sec |
  |-------------------|-----------|-------|
  | Pokéball Launcher | $15       | 0.1   |
  | Auto-Catcher NPC  | $100      | 1     |
  | Daycare Center    | $1,100    | 8     |
  | Pokémon Gym       | $12,000   | 47    |
  | Silph Co. Lab     | $130,000  | 260   |

  Buildings stay silhouetted until your lifetime earnings reach **60% of their base cost**,
  and stay muted while you can't afford them.
- **Evolution Items** (Fire Stone, Thunder Stone, Up-Grade…) are one-time purchases
  that **double the output** of their matching building; the Amulet Coin doubles your clicks.
- **Prestige — Pokémon League**: once your all-time lifetime earnings qualify, reset the
  run to earn **Gym Badges** (`floor(√(lifetime ÷ 1e8))`), each granting a **permanent +5%
  income bonus**. PC Box, lifetime stats and achievements are kept.

## Tracked stats

- **PokéDollars** — current spendable balance (big display, middle column)
- **DPS** — dollars per second, recomputed from buildings × item multipliers × badge bonus
- **Lifetime earnings** — high score across all runs (also feeds prestige badges)
- Total clicks, Pokémon caught, playtime, Gym Badges — plus 8 achievements

## Architecture notes

- **No frameworks**: vanilla HTML + Tailwind (Play CDN) + two classic scripts, so the
  game also runs from `file://`. All state lives in one serializable `state` object.
- **Game loop**: 100 ms `setInterval` tick accrues `dps × dt` (delta-time based, capped
  at 1 s so background tabs don't jackpot); the news ticker rotates every 15 s; DOM
  writes are guarded (`setText`) to avoid layout churn.
- **Autosave**: full state → `localStorage` every 10 s, plus on `beforeunload` /
  tab-hide and after every purchase. Loading is defensive — a corrupted save falls back
  to a fresh game instead of crashing.
- **Offline earnings**: on load, elapsed time since last save earns 50% of your DPS,
  capped at 8 hours — announced via a "Welcome back" toast.
- **Number formatting**: integers with commas up to 999,999; compact suffixes
  (`1.5M`, `2.3B`, `4.2T`…) above; DPS rates keep small decimals (`0.1/s`).
- **Animations**: Web Animations API (squish on click, 3-shake on catch w/ legendary
  variant), CSS float-up `+$x` popups at the exact cursor coordinates, toast stack,
  news crossfade. Fully responsive: 3 columns on desktop → stacked on mobile with
  `touch-action: manipulation` to kill double-tap zoom.

## Debugging

Open the browser console — a `PokeClicker` API is exposed:
`PokeClicker.state`, `PokeClicker.save()`, `PokeClicker.prestige()`,
`PokeClicker._debug.addCash(1000)`, `PokeClicker.fmt(1.5e6)`, …
