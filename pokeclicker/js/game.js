/* ============================================================================
 * PokéClicker — core game engine
 * Classic script (no modules so file:// keeps working). Requires js/data.js
 * to be loaded first (BUILDINGS, EVOLUTION_ITEMS, SPECIES, RARITIES,
 * NEWS_POOL, ACHIEVEMENTS).
 * ========================================================================== */
(function () {
'use strict';

/* ============================= Tunables =================================== */
const SAVE_KEY            = 'pokeclicker.save.v1';
const PRICE_GROWTH        = 1.15;   // cost(n) = ceil(baseCost * 1.15 ^ owned)
const CLICKS_PER_CATCH    = 100;    // a wild Pokémon appears every 100 clicks
const CATCH_BONUS_SECONDS = 30;     // catch bonus = max(25, dps * this)
const REVEAL_RATIO        = 0.6;    // shop entries reveal at 60% of cost
const ITEM_REVEAL_RATIO   = 0.5;    // evolution items reveal at 50% of cost
const OFFLINE_CAP_HOURS   = 8;      // offline earnings capped at this
const OFFLINE_EFFICIENCY  = 0.5;    // offline production runs at 50%
const CRIT_CHANCE         = 0.04;   // 4% critical clicks
const CRIT_MULT           = 7;
const BADGE_BONUS         = 0.05;   // +5% global income per Gym Badge
const BADGE_LIFETIME_BASE = 1e8;    // badges = floor(sqrt(lifetimeAll / 1e8))
const TICK_MS             = 100;
const AUTOSAVE_MS         = 10000;
const NEWS_MS             = 15000;

/* ============================= State ====================================== */
function defaultState() {
  return {
    balance: 0,          // current spendable PokéDollars
    lifetimeRun: 0,      // earned since last prestige
    lifetimeAll: 0,      // earned across all runs (high score)
    totalClicks: 0,
    clicksSinceCatch: 0, // progress toward the next wild encounter
    buildings: {},       // { buildingId: count }
    items: {},           // { itemId: true }
    species: {},         // { speciesId: { name, rarity, count } }
    achievements: {},    // { achId: true }
    badges: 0,           // prestige Gym Badges (+5% income each)
    totalCaught: 0,
    playtime: 0,         // active seconds
    lastSeen: Date.now(),
  };
}
let state = defaultState();

/* ======================= Number formatting ================================ */
const UNITS = ['', 'K', 'M', 'B', 'T', 'Qa', 'Qi', 'Sx', 'Sp', 'Oc', 'No', 'Dc'];

function trimZeros(str) {
  return str.indexOf('.') === -1 ? str : str.replace(/\.?0+$/, '');
}

/* Balances / costs / lifetime — integers under 1M, compact suffixes above. */
function fmt(n) {
  if (!isFinite(n)) return '∞';
  const neg = n < 0;
  n = Math.abs(n);
  let out;
  if (n < 1e6) {
    out = Math.floor(n).toLocaleString('en-US');
  } else {
    let u = 0, v = n;
    while (v >= 1000 && u < UNITS.length - 1) { v /= 1000; u++; }
    out = trimZeros(v.toFixed(v < 100 ? 2 : 1)) + UNITS[u];
  }
  return (neg ? '-' : '') + out;
}

/* Rates — keep small decimals readable (0.1/s launcher matters!). */
function fmtRate(n) {
  if (!isFinite(n)) return '∞';
  if (n >= 1e6)  return fmt(n);
  if (n >= 100)  return trimZeros(n.toFixed(0));
  if (n >= 10)   return trimZeros(n.toFixed(1));
  if (n >= 0.005) return trimZeros(n.toFixed(2));
  return '0';
}

function fmtDuration(sec) {
  sec = Math.floor(sec);
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  if (h > 0) return h + 'h ' + String(m).padStart(2, '0') + 'm';
  if (m > 0) return m + 'm ' + String(s).padStart(2, '0') + 's';
  return s + 's';
}

/* ===================== Derived stats / formulas =========================== */
function buildingById(id)   { return BUILDINGS.find((b) => b.id === id); }
function itemById(id)       { return EVOLUTION_ITEMS.find((i) => i.id === id); }
function ownedCount(id)     { return state.buildings[id] || 0; }

function buildingCost(id) {
  const b = buildingById(id);
  return Math.ceil(b.baseCost * Math.pow(PRICE_GROWTH, ownedCount(id)));
}

/* Multiplier on one building from purchased Evolution Items. */
function buildingMult(id) {
  let m = 1;
  for (const it of EVOLUTION_ITEMS) {
    if (it.target === id && state.items[it.id]) m *= it.mult;
  }
  return m;
}

function globalMult() { return 1 + state.badges * BADGE_BONUS; }

function buildingDps(id) {
  const b = buildingById(id);
  const n = ownedCount(id);
  return n * b.baseDps * buildingMult(id);
}

function rawDps() {
  let sum = 0;
  for (const b of BUILDINGS) sum += buildingDps(b.id);
  return sum;
}

function dps() { return rawDps() * globalMult(); }

function clickValue() {
  return (state.items['amulet-coin'] ? 2 : 1) * globalMult();
}

/* Prestige (Gym Badges): badges are derived from lifetime earnings. */
function pendingBadges() {
  return Math.max(0, Math.floor(Math.sqrt(state.lifetimeAll / BADGE_LIFETIME_BASE)) - state.badges);
}
function nextBadgeAt() {
  const k = state.badges + pendingBadges() + 1;
  return k * k * BADGE_LIFETIME_BASE;
}

/* ============================ Economy ===================================== */
function earn(amount) {
  if (!(amount > 0)) return;
  state.balance     += amount;
  state.lifetimeRun += amount;
  state.lifetimeAll += amount;
}

function buyBuilding(id) {
  const b = buildingById(id);
  if (!b) return false;
  const cost = buildingCost(id);
  if (state.balance < cost) return false;
  state.balance -= cost;
  const first = ownedCount(id) === 0;
  state.buildings[id] = ownedCount(id) + 1;
  if (first) {
    pushNews(b.name + ' fired up for the first time. The local economy trembles.');
  }
  refreshShop();
  renderStats();
  flashRow('building-' + id);
  evalAchievements();
  save();
  return true;
}

function buyItem(id) {
  const it = itemById(id);
  if (!it || state.items[id]) return false;
  if (state.balance < it.cost) return false;
  state.balance -= it.cost;
  state.items[id] = true;
  toast(
    '<img class="pixel" src="' + it.icon + '" alt="">' +
    '<span><b>' + it.name + '</b> used!<br>' + it.desc + '</span>',
    'uncommon'
  );
  pushNews('Rumors swirl after a trainer used a ' + it.name + ' on the local economy.');
  refreshShop();
  renderStats();
  flashRow('item-' + id);
  evalAchievements();
  save();
  return true;
}

/* ===================== Clicking & Catching ================================ */
function onBallClick(x, y) {
  let value = clickValue();
  let crit = false;
  if (Math.random() < CRIT_CHANCE) { value *= CRIT_MULT; crit = true; }
  earn(value);
  state.totalClicks++;
  state.clicksSinceCatch++;

  squishBall();
  spawnPopup(x, y, (crit ? 'CRITICAL +$' : '+$') + fmtRate(value), crit);

  if (state.clicksSinceCatch >= CLICKS_PER_CATCH) {
    state.clicksSinceCatch -= CLICKS_PER_CATCH;
    doCatch();
  }
  renderStats();
  renderCatchProgress();
}

function pickSpecies() {
  const totalW = RARITIES.reduce((a, r) => a + r.weight, 0);
  let roll = Math.random() * totalW;
  let rarity = RARITIES[0];
  for (const r of RARITIES) { if (roll < r.weight) { rarity = r; break; } roll -= r.weight; }
  const pool = SPECIES.filter((s) => s.rarity === rarity.id);
  return pool[Math.floor(Math.random() * pool.length)];
}

function doCatch() {
  const sp = pickSpecies();
  const rec = state.species[sp.id] ||
    (state.species[sp.id] = { name: sp.name, rarity: sp.rarity, count: 0 });
  rec.count++;
  state.totalCaught++;

  const bonus = Math.max(25, Math.ceil(dps() * CATCH_BONUS_SECONDS));
  earn(bonus);

  updatePcBoxCell(String(sp.id), sp, rec.count);
  shakeBall(sp.rarity === 'legendary');
  toast(
    '<img class="pixel" src="assets/sprites/pokemon/' + sp.id + '.png" alt="' + sp.name + '">' +
    '<span>A wild <b>' + sp.name + '</b> was caught' + (rec.count > 1 ? ' (×' + rec.count + ')' : '') +
    '!<br>Stored in the PC Box. <b>+$' + fmt(bonus) + '</b> bonus!</span>',
    sp.rarity
  );
  pushNews(catchNews(sp));
  refreshShop(); // balance changed → affordability may flip
  renderStats();
  evalAchievements();
}

function catchNews(sp) {
  switch (sp.rarity) {
    case 'legendary':
      return 'BREAKING: a ' + sp.name + ' was just caught by raw clicking power. Scientists are baffled.';
    case 'rare':
      return 'Eyewitnesses confirm a ' + sp.name + ' was caught near the Pokéball arena.';
    case 'uncommon':
      return 'A ' + sp.name + ' joins the PC Box after a dramatic 100-click battle.';
    default:
      return 'Another ' + sp.name + ' caught. It seems happy to help the economy.';
  }
}

/* ============================ Prestige ==================================== */
function doPrestige() {
  const gain = pendingBadges();
  if (gain < 1) return;
  const msg =
    'Challenge the Pokémon League?\n\n' +
    'This resets the current run (balance, buildings, Evolution Items) and awards ' +
    gain + ' Gym Badge' + (gain > 1 ? 's' : '') + '.\n' +
    'Each Gym Badge permanently boosts ALL income by +5%.\n\n' +
    'Lifetime stats, caught Pokémon and achievements are kept.';
  if (!window.confirm(msg)) return;

  state.badges += gain;
  state.balance = 0;
  state.lifetimeRun = 0;
  state.buildings = {};
  state.items = {};
  state.clicksSinceCatch = 0;

  toast(
    '<img class="pixel" src="assets/sprites/items/master-ball.png" alt="">' +
    '<span><b>League conquered!</b> +' + gain + ' Gym Badge' + (gain > 1 ? 's' : '') +
    ' — permanent +' + gain * BADGE_BONUS * 100 + '% income.</span>',
    'legendary'
  );
  pushNews('Local trainer defeats the Elite Four using only an overworked index finger.');
  refreshShop();
  renderStats();
  renderCatchProgress();
  updatePrestigePanel();
  evalAchievements();
  save();
}

/* ========================= Save / Load / Reset ============================ */
function save() {
  try {
    state.lastSeen = Date.now();
    window.localStorage.setItem(SAVE_KEY, JSON.stringify(state));
    markSaved();
  } catch (err) { /* storage unavailable (private mode) — keep playing in-memory */ }
}

function sanitizeNumber(v, fallback) {
  return (typeof v === 'number' && isFinite(v) && v >= 0) ? v : fallback;
}

function load() {
  let raw;
  try { raw = window.localStorage.getItem(SAVE_KEY); } catch (err) { return false; }
  if (!raw) return false;
  let data;
  try { data = JSON.parse(raw); } catch (err) { return false; }
  if (!data || typeof data !== 'object') return false;

  const s = Object.assign(defaultState(), data);
  // Defensive normalization so a corrupted save can never crash the game.
  for (const k of ['balance', 'lifetimeRun', 'lifetimeAll', 'totalClicks',
    'clicksSinceCatch', 'badges', 'totalCaught', 'playtime', 'lastSeen']) {
    s[k] = sanitizeNumber(s[k], 0);
  }
  if (!s.lastSeen) s.lastSeen = Date.now();
  for (const mapName of ['buildings', 'species']) {
    if (!s[mapName] || typeof s[mapName] !== 'object') s[mapName] = {};
  }
  for (const setName of ['items', 'achievements']) {
    if (!s[setName] || typeof s[setName] !== 'object') s[setName] = {};
  }
  const cleanBuildings = {};
  for (const b of BUILDINGS) {
    const n = Math.floor(sanitizeNumber(s.buildings[b.id], 0));
    if (n > 0) cleanBuildings[b.id] = n;
  }
  s.buildings = cleanBuildings;
  const cleanSpecies = {};
  for (const id of Object.keys(s.species)) {
    const rec = s.species[id];
    if (!rec || typeof rec !== 'object') continue;
    const sp = SPECIES.find((x) => String(x.id) === String(id));
    if (!sp) continue;
    cleanSpecies[String(sp.id)] = {
      name: sp.name, rarity: sp.rarity,
      count: Math.max(1, Math.floor(sanitizeNumber(rec.count, 1))),
    };
  }
  s.species = cleanSpecies;

  state = s;
  return true;
}

function hardReset() {
  if (!window.confirm(
    'Release EVERYTHING and start a brand-new adventure?\n\n' +
    'This wipes your save: money, buildings, badges and the entire PC Box.'
  )) return;
  try { window.localStorage.removeItem(SAVE_KEY); } catch (err) { /* ignore */ }
  window.location.reload();
}

function applyOfflineProgress() {
  const now = Date.now();
  const elapsed = Math.max(0, (now - state.lastSeen) / 1000);
  const capped = Math.min(elapsed, OFFLINE_CAP_HOURS * 3600);
  const gain = Math.floor(dps() * capped * OFFLINE_EFFICIENCY);
  state.lastSeen = now;
  if (gain >= 10 && capped >= 30) {
    earn(gain);
    window.setTimeout(function () {
      toast(
        '<img class="pixel" src="assets/sprites/items/great-ball.png" alt="">' +
        '<span><b>Welcome back!</b> Your team earned <b>$' + fmt(gain) + '</b> while you were away (' +
        fmtDuration(capped) + ', ' + Math.round(OFFLINE_EFFICIENCY * 100) + '% efficiency).</span>',
        'info'
      );
    }, 600);
  }
}

/* ======================= DOM refs & building ============================== */
const el = {};
function $(id) { return document.getElementById(id); }

function cacheRefs() {
  for (const id of [
    'arena', 'ballBtn', 'ballScale', 'ballShake',
    'statBalance', 'statDps', 'statPerClick',
    'statLifetime', 'statClicks', 'statCaught', 'statPlaytime', 'statBadges',
    'catchProgressFill', 'catchProgressText',
    'newsTicker',
    'shopBalance', 'shopBuildings', 'shopItems',
    'prestigeInfo', 'prestigeNext', 'prestigeBtn',
    'achGrid', 'pcBox', 'pcEmpty',
    'toasts', 'saveStatus', 'saveBtn', 'resetBtn',
  ]) el[id] = $(id);
}

function setText(node, text) {         // avoid pointless DOM churn
  if (node && node.__lastText !== text) {
    node.__lastText = text;
    node.textContent = text;
  }
}

/* --- Shop --- */
const shopRefs = []; // { kind, data, row, icon, name, sub, cost, ownedBadge }

function buildShop() {
  el.shopBuildings.textContent = '';
  el.shopItems.textContent = '';
  shopRefs.length = 0;

  for (const b of BUILDINGS) {
    const row = document.createElement('button');
    row.type = 'button';
    row.id = 'building-' + b.id;
    row.dataset.kind = 'building';
    row.dataset.id = b.id;
    row.className =
      'shop-row relative w-full text-left flex items-center gap-3 rounded-xl border-2 ' +
      'border-slate-200/80 bg-white/80 p-2.5 transition-colors no-select';
    row.setAttribute('aria-label', 'Buy ' + b.name);
    row.innerHTML =
      '<span class="relative flex-none w-12 h-12 grid place-items-center rounded-lg bg-sky-100/70 border border-sky-200">' +
        '<img class="pixel icon-img w-9 h-9" src="' + b.icon + '" alt="" draggable="false">' +
        '<span class="owned-badge absolute -bottom-1.5 -right-1.5 min-w-[1.4rem] px-1 rounded-full ' +
          'bg-poke-navy text-white text-[0.65rem] font-bold text-center leading-[1.1rem]">0</span>' +
      '</span>' +
      '<span class="min-w-0 flex-1">' +
        '<span class="shop-name block font-bold text-poke-navy truncate">' + b.name + '</span>' +
        '<span class="shop-sub block text-xs text-slate-500 truncate"></span>' +
      '</span>' +
      '<span class="cost-chip flex-none rounded-full bg-poke-red text-white font-bold text-sm px-3 py-1 ' +
        'shadow whitespace-nowrap"></span>';
    el.shopBuildings.appendChild(row);
    shopRefs.push({
      kind: 'building', data: b, row: row,
      icon: row.querySelector('.icon-img'),
      name: row.querySelector('.shop-name'),
      sub: row.querySelector('.shop-sub'),
      cost: row.querySelector('.cost-chip'),
      ownedBadge: row.querySelector('.owned-badge'),
    });
  }

  for (const it of EVOLUTION_ITEMS) {
    const row = document.createElement('button');
    row.type = 'button';
    row.id = 'item-' + it.id;
    row.dataset.kind = 'item';
    row.dataset.id = it.id;
    row.className =
      'shop-row relative w-full text-left flex items-center gap-3 rounded-xl border-2 ' +
      'border-amber-200/80 bg-white/80 p-2.5 transition-colors no-select';
    row.setAttribute('aria-label', 'Use ' + it.name);
    row.innerHTML =
      '<span class="flex-none w-12 h-12 grid place-items-center rounded-lg bg-amber-100/60 border border-amber-200">' +
        '<img class="pixel icon-img w-9 h-9" src="' + it.icon + '" alt="" draggable="false">' +
      '</span>' +
      '<span class="min-w-0 flex-1">' +
        '<span class="shop-name block font-bold text-poke-navy truncate">' + it.name + '</span>' +
        '<span class="shop-sub block text-xs text-slate-500"></span>' +
      '</span>' +
      '<span class="cost-chip flex-none rounded-full bg-poke-blue text-white font-bold text-sm px-3 py-1 ' +
        'shadow whitespace-nowrap"></span>';
    el.shopItems.appendChild(row);
    shopRefs.push({
      kind: 'item', data: it, row: row,
      icon: row.querySelector('.icon-img'),
      name: row.querySelector('.shop-name'),
      sub: row.querySelector('.shop-sub'),
      cost: row.querySelector('.cost-chip'),
      ownedBadge: null,
    });
  }
}

function isBuildingVisible(b) { return state.lifetimeAll >= b.baseCost * REVEAL_RATIO; }

function isItemVisible(it) {
  if (state.lifetimeAll < it.cost * ITEM_REVEAL_RATIO) return false;
  if (it.target && ownedCount(it.target) < 1) return false;
  return true;
}

/* Single shop refresh — setText() guards make it cheap to run every tick.
 * Handles texts (cost/owned/effect), reveal/un-reveal silhouettes and
 * affordability classes for both buildings and evolution items.          */
function refreshShop() {
  for (const ref of shopRefs) {
    const row = ref.row;
    if (ref.kind === 'building') {
      const b = ref.data;
      const owned = ownedCount(b.id);
      const visible = isBuildingVisible(b);
      const afford = visible && state.balance >= buildingCost(b.id);
      setText(ref.ownedBadge, String(owned));
      setText(ref.name, visible ? b.name : '???');
      setText(ref.sub, visible
        ? fmtRate(b.baseDps * buildingMult(b.id)) + '/s each · total ' +
          fmtRate(buildingDps(b.id) * globalMult()) + '/s'
        : b.tagline);
      setText(ref.cost, visible ? '$' + fmt(buildingCost(b.id)) : '🔒');
      row.classList.toggle('locked', !visible);
      row.classList.toggle('affordable', afford);
      ref.cost.classList.toggle('chip-afford', afford);
      row.disabled = !afford;
    } else {
      const it = ref.data;
      const owned = !!state.items[it.id];
      const visible = isItemVisible(it);
      const afford = !owned && visible && state.balance >= it.cost;
      setText(ref.name, visible || owned ? it.name : '???');
      let sub;
      if (owned || visible) {
        sub = it.desc;
      } else if (it.target && state.lifetimeAll >= it.cost * ITEM_REVEAL_RATIO) {
        sub = 'Requires a ' + buildingById(it.target).name + ' first.';
      } else {
        sub = 'Reach $' + fmt(it.cost * ITEM_REVEAL_RATIO) + ' lifetime to reveal.';
      }
      setText(ref.sub, sub);
      setText(ref.cost, owned ? 'OWNED ✓' : visible ? '$' + fmt(it.cost) : '🔒');
      row.classList.toggle('locked', !owned && !visible);
      row.classList.toggle('owned', owned);
      row.classList.toggle('affordable', afford);
      ref.cost.classList.toggle('chip-afford', afford);
      row.disabled = owned || !afford;
    }
  }
}

function flashRow(rowId) {
  const row = $(rowId);
  if (!row) return;
  row.classList.remove('row-flash');
  void row.offsetWidth; // restart the animation
  row.classList.add('row-flash');
}

/* --- Stats / header --- */
function markSaved() {
  if (!el.saveStatus) return;
  const t = new Date();
  const hh = String(t.getHours()).padStart(2, '0');
  const mm = String(t.getMinutes()).padStart(2, '0');
  const ss = String(t.getSeconds()).padStart(2, '0');
  setText(el.saveStatus, 'Saved ' + hh + ':' + mm + ':' + ss);
}

function renderStats() {
  setText(el.statBalance, fmt(state.balance));
  setText(el.shopBalance, fmt(state.balance));
  setText(el.statDps, fmtRate(dps()));
  setText(el.statPerClick, fmtRate(clickValue()));
  setText(el.statLifetime, fmt(state.lifetimeAll));
  setText(el.statClicks, fmt(state.totalClicks));
  setText(el.statCaught, fmt(state.totalCaught));
  setText(el.statPlaytime, fmtDuration(state.playtime));
  setText(el.statBadges, state.badges > 0
    ? state.badges + ' (+' + state.badges * BADGE_BONUS * 100 + '%)'
    : '—');
}

function renderCatchProgress() {
  const pct = Math.round((state.clicksSinceCatch / CLICKS_PER_CATCH) * 100);
  el.catchProgressFill.style.width = pct + '%';
  setText(el.catchProgressText,
    state.clicksSinceCatch + ' / ' + CLICKS_PER_CATCH + ' clicks to the next wild encounter');
}

function updatePrestigePanel() {
  const gain = pendingBadges();
  if (gain >= 1) {
    setText(el.prestigeInfo,
      'Reset this run to earn ' + gain + ' Gym Badge' + (gain > 1 ? 's' : '') +
      ' (+' + gain * BADGE_BONUS * 100 + '% permanent income).');
    el.prestigeBtn.disabled = false;
  } else {
    setText(el.prestigeInfo,
      'You have ' + state.badges + ' badge' + (state.badges === 1 ? '' : 's') + '. Next badge at $' +
      fmt(nextBadgeAt()) + ' lifetime earnings (this awards all pending badges at once).');
    el.prestigeBtn.disabled = true;
  }
}

/* --- Achievements --- */
const achTileRefs = {};
function buildAchievements() {
  el.achGrid.textContent = '';
  for (const a of ACHIEVEMENTS) {
    const tile = document.createElement('div');
    tile.className = 'ach-tile flex flex-col items-center text-center gap-1';
    tile.id = 'ach-' + a.id;
    tile.title = a.name + ' — ' + a.desc;
    tile.innerHTML =
      '<span class="ach-ring w-12 h-12 grid place-items-center rounded-full border-2 ' +
        'border-slate-300 bg-slate-100">' +
        '<img class="pixel w-8 h-8" src="' + a.icon + '" alt="">' +
      '</span>' +
      '<span class="text-[0.62rem] leading-tight font-semibold text-poke-navy">' + a.name + '</span>';
    el.achGrid.appendChild(tile);
    achTileRefs[a.id] = tile;
  }
  // Restore already-unlocked tiles from a loaded save.
  for (const id of Object.keys(state.achievements)) {
    if (achTileRefs[id]) achTileRefs[id].classList.add('unlocked');
  }
}

function evalAchievements() {
  for (const a of ACHIEVEMENTS) {
    if (state.achievements[a.id]) continue;
    let ok = false;
    try { ok = !!a.check(state); } catch (err) { ok = false; }
    if (ok) {
      state.achievements[a.id] = true;
      const tile = achTileRefs[a.id];
      if (tile) tile.classList.add('unlocked');
      toast(
        '<img class="pixel" src="' + a.icon + '" alt="">' +
        '<span><b>Achievement unlocked!</b><br>' + a.name + ' — ' + a.desc + '</span>',
        'legendary'
      );
    }
  }
}

/* --- PC Box --- */
const pcCells = {};
function renderPcBox() {
  el.pcBox.textContent = '';
  for (const id of Object.keys(pcCells)) delete pcCells[id];
  const ids = Object.keys(state.species);
  el.pcEmpty.style.display = ids.length ? 'none' : '';
  for (const id of ids) {
    const rec = state.species[id];
    const sp = SPECIES.find((x) => String(x.id) === id);
    if (!sp) continue;
    createPcBoxCell(id, sp, rec.count);
  }
}

function createPcBoxCell(id, sp, count) {
  const cell = document.createElement('div');
  cell.className = 'pc-cell pop-in' + (sp.rarity === 'legendary' ? ' legendary' : '');
  cell.dataset.id = id;
  cell.title = sp.name + ' — caught ' + count;
  cell.innerHTML =
    '<span class="pc-count">×' + count + '</span>' +
    '<img class="pixel w-10 h-10" src="assets/sprites/pokemon/' + id + '.png" alt="' + sp.name + '">' +
    '<span class="text-[0.62rem] font-semibold text-poke-navy leading-none">' + sp.name + '</span>';
  el.pcBox.appendChild(cell);
  pcCells[id] = cell;
  el.pcEmpty.style.display = 'none';
  return cell;
}

function updatePcBoxCell(id, sp, count) {
  const cell = pcCells[id];
  if (cell) {
    cell.title = sp.name + ' — caught ' + count;
    const badge = cell.querySelector('.pc-count');
    if (badge) badge.textContent = '×' + count;
    cell.classList.remove('pop-in');
    void cell.offsetWidth;
    cell.classList.add('pop-in');
  } else {
    createPcBoxCell(id, sp, count);
  }
}

/* --- Toasts --- */
function toast(html, kind) {
  const wrap = el.toasts;
  if (!wrap) return;
  while (wrap.children.length >= 4) wrap.removeChild(wrap.firstChild);
  const t = document.createElement('div');
  t.className = 'toast toast-' + (kind || 'info');
  t.setAttribute('role', 'status');
  t.innerHTML = html;
  wrap.appendChild(t);
  requestAnimationFrame(function () { t.classList.add('toast-in'); });
  window.setTimeout(function () {
    t.classList.remove('toast-in');
    t.classList.add('toast-out');
    window.setTimeout(function () { t.remove(); }, 380);
  }, 4300);
}

/* --- Click popups & ball animation --- */
function spawnPopup(x, y, text, crit) {
  const arena = el.arena;
  const rect = arena.getBoundingClientRect();
  const s = document.createElement('span');
  s.className = 'click-popup' + (crit ? ' crit' : '');
  s.textContent = text;
  const left = Math.min(Math.max(x - rect.left, 40), Math.max(rect.width - 40, 40));
  const top = Math.min(Math.max(y - rect.top, 16), Math.max(rect.height - 16, 16));
  s.style.left = left + 'px';
  s.style.top = top + 'px';
  s.style.setProperty('--dx', (Math.random() * 48 - 24) + 'px');
  arena.appendChild(s);
  s.addEventListener('animationend', function () { s.remove(); });
  window.setTimeout(function () { if (s.isConnected) s.remove(); }, 1500);
}

function squishBall() {
  const b = el.ballScale;
  if (b && b.animate) {
    b.animate(
      [{ transform: 'scale(1)' }, { transform: 'scale(0.93)' },
       { transform: 'scale(1.04)' }, { transform: 'scale(1)' }],
      { duration: 170, easing: 'ease-out' }
    );
  }
}

function shakeBall(strong) {
  const w = el.ballShake;
  if (w && w.animate) {
    const r = strong ? 15 : 9;
    w.animate(
      [{ transform: 'rotate(0deg)' }, { transform: 'rotate(' + -r + 'deg)' },
       { transform: 'rotate(' + r + 'deg)' }, { transform: 'rotate(' + -r * 0.6 + 'deg)' },
       { transform: 'rotate(' + r * 0.6 + 'deg)' }, { transform: 'rotate(0deg)' }],
      { duration: strong ? 900 : 650, easing: 'ease-in-out' }
    );
  }
}

/* --- News ticker --- */
let newsBag = [];
let newsPos = 0;
let newsTimer = null;

function shuffled(arr) {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    const tmp = a[i]; a[i] = a[j]; a[j] = tmp;
  }
  return a;
}

function showNews(text) {
  const t = el.newsTicker;
  t.classList.add('news-fade-out');
  window.setTimeout(function () {
    setText(t, text);
    t.classList.remove('news-fade-out');
  }, 300);
}

function nextNews() {
  if (newsPos >= newsBag.length) { newsBag = shuffled(NEWS_POOL); newsPos = 0; }
  showNews(newsBag[newsPos++]);
}

function pushNews(text) {   // event-driven messages reset the 15 s rotation
  showNews(text);
  if (newsTimer) window.clearInterval(newsTimer);
  newsTimer = window.setInterval(nextNews, NEWS_MS);
}

/* ============================ Game loop =================================== */
let lastTick = 0;
let secondAcc = 0;

function tick() {
  const now = performance.now();
  let dt = (now - lastTick) / 1000;
  lastTick = now;
  if (dt <= 0) return;
  if (dt > 1) dt = 1;              // background tabs: no giant catch-up jumps

  const prod = dps() * dt;
  if (prod > 0) earn(prod);
  state.playtime += dt;

  renderStats();
  refreshShop();

  secondAcc += dt;
  if (secondAcc >= 1) {
    secondAcc %= 1;
    evalAchievements();
    updatePrestigePanel();
  }
}

/* ============================ Events ======================================= */
function bindEvents() {
  el.ballBtn.addEventListener('click', function (e) {
    let x = e.clientX, y = e.clientY;
    if (!x && !y) {                       // keyboard activation (Enter/Space)
      const r = el.ballBtn.getBoundingClientRect();
      x = r.left + r.width / 2;
      y = r.top + r.height / 2;
    }
    onBallClick(x, y);
  });
  el.arena.addEventListener('contextmenu', function (e) { e.preventDefault(); });

  // Event delegation for the whole shop (works for both lists).
  document.getElementById('shopCard').addEventListener('click', function (e) {
    const row = e.target.closest('.shop-row');
    if (!row || row.disabled) return;
    if (row.dataset.kind === 'building') buyBuilding(row.dataset.id);
    else buyItem(row.dataset.id);
  });

  el.prestigeBtn.addEventListener('click', doPrestige);

  el.saveBtn.addEventListener('click', function () {
    save();
    toast(
      '<img class="pixel" src="assets/sprites/items/poke-ball.png" alt="">' +
      '<span><b>Progress saved.</b> Professor Oak would be proud.</span>',
      'info'
    );
  });
  el.resetBtn.addEventListener('click', hardReset);

  window.addEventListener('beforeunload', save);
  document.addEventListener('visibilitychange', function () {
    if (document.hidden) save();
  });
}

/* ============================ Debug / console API ========================= */
function exposeDebug() {
  window.PokeClicker = {
    get state() { return state; },
    fmt: fmt, fmtRate: fmtRate,
    dps: dps, clickValue: clickValue,
    buildingCost: buildingCost, pendingBadges: pendingBadges,
    buyBuilding: buyBuilding, buyItem: buyItem,
    prestige: doPrestige,
    save: save, load: load, reset: hardReset,
    version: '1.0.0',
    _debug: {
      addCash: function (n) { earn(n); renderStats(); refreshShop(); },
      catchNow: doCatch,
    },
  };
}

/* ============================ Init ======================================== */
function refreshAll() {
  renderPcBox();
  refreshShop();
  renderStats();
  renderCatchProgress();
  updatePrestigePanel();
}

function init() {
  cacheRefs();
  buildShop();
  buildAchievements();
  const hadSave = load();
  if (hadSave) applyOfflineProgress();
  refreshAll();
  exposeDebug();
  bindEvents();

  newsBag = shuffled(NEWS_POOL); newsPos = 0;
  showNews(hadSave
    ? 'Welcome back to the tall grass! Your PC Box missed you.'
    : 'Welcome to PokéClicker! Click the Pokéball to earn your very first PokéDollar.');
  newsTimer = window.setInterval(nextNews, NEWS_MS);

  lastTick = performance.now();
  window.setInterval(tick, TICK_MS);
  window.setInterval(save, AUTOSAVE_MS);
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}

})();
