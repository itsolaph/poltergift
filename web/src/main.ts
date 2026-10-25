import { CHARGED, CLAIM_FEE, DemoRound, GIFT, type Outcome } from "./demo";
import { EXPLORER, assertComponent, assertTx, epoch, fetchRound, loadDeployment, loadSnapshot, type LiveRound } from "./live";
import { loadWasm, short, tari } from "./pg";

const $ = <T extends HTMLElement = HTMLElement>(sel: string) => document.querySelector(sel) as T;
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const COLORS = ["#e9e4ff", "#c7f9e1", "#ffd9f2", "#d6ecff", "#fff1c9", "#e2ffd1", "#ffe0d1", "#dcd6ff"];
const ghostSvg = (color: string) => `
  <svg viewBox="0 0 64 64" aria-hidden="true">
    <path d="M32 6c-12 0-20 9-20 21v27l6-5 5 5 5-5 4 5 4-5 5 5 5-5 6 5V27C52 15 44 6 32 6z" fill="${color}"/>
    <circle cx="25" cy="27" r="4" fill="#120f1d"/><circle cx="39" cy="27" r="4" fill="#120f1d"/>
    <ellipse cx="32" cy="38" rx="4" ry="3" fill="#120f1d"/>
  </svg>`;

// ------------------------------------------------------------------------------------------------
// Summon 5 Ghosts
// ------------------------------------------------------------------------------------------------

let round: DemoRound | null = null;
let stage = 0; // 0 = nothing, 1 = created, 2.. = progress
let queue: (() => string)[] = [];
let selected = 0;
let running = false;

function setStep(n: number) {
  document.querySelectorAll<HTMLLIElement>("#steps li").forEach((li) => {
    const s = Number(li.dataset.step);
    li.classList.toggle("done", s < n);
    li.classList.toggle("current", s === n);
  });
}

function log(msg: string) {
  const el = $("#log");
  el.innerHTML = msg;
  el.classList.remove("fresh");
  void el.offsetWidth;
  el.classList.add("fresh");
}

function expect(o: Outcome, what: string) {
  if (!o.ok) throw new Error(`${what} rejected: ${o.message}`);
}

function plan(r: DemoRound): (() => string)[] {
  const steps: (() => string)[] = [];
  steps.push(() => {
    expect(r.create(), "create");
    setStep(1);
    return `A haunted round opens: ${r.size} ghosts × ${tari(GIFT)}, claim fee ${tari(CLAIM_FEE)}.`;
  });
  r.ghosts.forEach((g, i) =>
    steps.push(() => {
      expect(r.join(i), `${g.name}'s join`);
      if (r.view?.sealed) {
        setStep(3);
        return `${g.name} drops the last gift: the round is <b>sealed</b>, the ring of ${r.size} member keys is fixed.`;
      }
      return `${g.name} drops a gift under a fresh member key ${short(g.member.public)} (proof of possession checked).`;
    }),
  );
  const order = r.ghosts.map((_, i) => i);
  for (let i = order.length - 1; i > 0; i--) {
    const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
    [order[i], order[j]] = [order[j], order[i]];
  }
  order.forEach((i, n) =>
    steps.push(() => {
      expect(r.claim(i), `${r.ghosts[i].name}'s claim`);
      const last = n === order.length - 1;
      if (last) setStep(5);
      return `A ghost claims with a ring signature and tag ${short(r.ghosts[i].tag ?? "")}: one of ${r.size}, never which.${last ? " Every ghost now holds exactly one gift." : ""}`;
    }),
  );
  return steps;
}

function reset() {
  round = new DemoRound(5);
  queue = plan(round);
  stage = 0;
  selected = 0;
  setStep(0);
  $("#lab-results").innerHTML = "";
  log("Press <b>Summon 5 Ghosts</b>: a full round runs in your browser in about 15 seconds.");
  renderAll();
}

function stepOnce(): boolean {
  const next = queue.shift();
  if (!next || !round) return false;
  try {
    log(next());
  } catch (e) {
    log(`<span style="color:var(--red)">${esc(String(e))}</span>`);
    queue = [];
    return false;
  }
  stage++;
  renderAll();
  return queue.length > 0;
}

async function runAll() {
  if (running) return;
  running = true;
  updateButtons();
  if (!queue.length) reset();
  const delay = () => Number(($("#speed") as HTMLSelectElement).value);
  while (stepOnce()) await sleep(delay());
  running = false;
  updateButtons();
}

function updateButtons() {
  ($("#run") as HTMLButtonElement).disabled = running;
  ($("#step") as HTMLButtonElement).disabled = running || queue.length === 0;
  ($("#reset") as HTMLButtonElement).disabled = running;
}

function renderGhosts() {
  if (!round) return;
  $("#ghosts").innerHTML = round.ghosts
    .map((g, i) => {
      const state = g.claimed ? "claimed" : g.joined ? "joined" : "waiting";
      return `<div class="ghost ${state} ${i === selected ? "selected" : ""}" data-i="${i}" title="Show ${esc(g.name)}'s recipient view">
        ${ghostSvg(COLORS[i % COLORS.length])}
        <div class="name">${esc(g.name)}</div>
        <div class="key">${short(g.member.public)}</div>
        <span class="pill ${state}">${state === "claimed" ? "holds a gift" : state === "joined" ? "gift dropped" : "waiting"}</span>
      </div>`;
    })
    .join("");
  document.querySelectorAll<HTMLDivElement>(".ghost").forEach((el) =>
    el.addEventListener("click", () => {
      selected = Number(el.dataset.i);
      renderGhosts();
      renderRecipient();
    }),
  );
}

function renderObserver() {
  if (!round) return;
  const deposits = round.deposits
    .map((d, i) => `<li><span class="mono">#${i} ${short(d.member)}</span><span class="amt">+${tari(d.amount)}</span></li>`)
    .join("");
  const payouts = round.payouts
    .map(
      (p) =>
        `<li><span class="mono">tag ${short(p.tag)} → owner ${short(p.output.owner_key)}</span><span class="no">amount sealed</span></li>`,
    )
    .join("");
  $("#observer").innerHTML = `
    <h3>Deposits (member keys)</h3>
    <ul class="rows">${deposits || `<li class="muted">none yet</li>`}</ul>
    <h3>Claims (tags → fresh outputs)</h3>
    <ul class="rows">${payouts || `<li class="muted">none yet</li>`}</ul>
    <p class="note">Every deposit is the same amount, and every payout spends the same public ${tari(round.view?.payout ?? 0)} from the vault into a fresh output whose value is hidden in a commitment. Every claim is signed by a throwaway key, pays its fee from the round, and shows only a tag and a brand-new one-time owner key. Nothing in these two lists says which row goes with which.</p>`;
}

function renderRecipient() {
  if (!round) return;
  const g = round.ghosts[selected];
  const picker = round.ghosts
    .map((x, i) => `<button data-i="${i}" class="${i === selected ? "active" : ""}">${esc(x.name)}</button>`)
    .join("");
  let body = `<p class="muted">${esc(g.name)} has not joined yet.</p>`;
  if (g.joined) {
    const myTag = round.keyImageOf(selected);
    const opens = round.openAll(selected);
    const rows = round.payouts
      .map((p, k) => {
        const amt = opens[k];
        return `<li><span class="mono">output ${short(p.output.owner_key)}</span>${
          amt === null ? `<span class="no">🔒 sealed</span>` : `<span class="ok">🔓 ${tari(amt)}</span>`
        }</li>`;
      })
      .join("");
    const spent = round.view?.spent_tags.includes(myTag);
    body = `
      <ul class="rows">
        <li><span>member key</span><span class="mono">${short(g.member.public)}</span></li>
        <li><span>my tag (from my secret)</span><span class="mono">${short(myTag)}</span></li>
        <li><span>tag on chain?</span><span class="${spent ? "ok" : "no"}">${spent ? "yes: I claimed" : "not yet"}</span></li>
      </ul>
      <h3>Trying every payout with ${esc(g.name)}'s wallet key</h3>
      <ul class="rows">${rows || `<li class="muted">no payouts yet</li>`}</ul>
      <p class="note">Only the holder of the destination's view key can recompute the one-time key and decrypt the amount. The tag is recognisable only to whoever knows the member secret.</p>`;
  }
  $("#recipient").innerHTML = `<div class="picker">${picker}</div>${body}`;
  document.querySelectorAll<HTMLButtonElement>("#recipient .picker button").forEach((b) =>
    b.addEventListener("click", () => {
      selected = Number(b.dataset.i);
      renderGhosts();
      renderRecipient();
    }),
  );
}

function renderAuditor() {
  if (!round || !round.view) {
    $("#auditor").innerHTML = `<p class="muted">The round has not been opened yet.</p>`;
    return;
  }
  const v = round.view;
  const deposited = v.joined * GIFT;
  const paidOut = (v.claims + v.refunds) * v.payout;
  const fees = round.feesCharged;
  const balanced = deposited === paidOut + fees + v.vault;
  $("#auditor").innerHTML = `
    <div class="totals">
      <span>Deposited (${v.joined} × ${tari(GIFT)})</span><span class="v">${tari(deposited)}</span>
      <span>Paid out (${v.claims + v.refunds} × ${tari(v.payout)})</span><span class="v">${tari(paidOut)}</span>
      <span>Network fees (≈${tari(CHARGED)} per claim)</span><span class="v">${tari(fees)}</span>
      <span>Left in the round vault</span><span class="v">${tari(v.vault)}</span>
      <span>Gifts still owed</span><span class="v">${v.outstanding}</span>
    </div>
    <div class="check ${balanced && v.solvent ? "" : "bad"}">
      ${balanced ? "✔ deposited = paid out + fees + vault" : "✘ totals do not balance"}<br/>
      ${v.solvent ? "✔ the vault can pay every gift still owed" : "✘ vault cannot cover outstanding gifts"}
    </div>
    <p class="note">TARI on Esmeralda has no resource view key and the round vault is a revealed vault, so these totals are public: an auditor needs no special key, and learns nothing about who received which gift.</p>`;
}

const ATTACKS: [string, (r: DemoRound) => Outcome][] = [
  ["Double claim", (r) => r.attackDoubleClaim()],
  ["Outsider claim", (r) => r.attackOutsider()],
  ["Redirect a payout", (r) => r.attackRedirect()],
  ["Replay from another round", (r) => r.attackReplay()],
  ["Early refund", (r) => r.attackEarlyRefund()],
  ["Wrong gift amount", (r) => r.attackWrongGift()],
  ["Register someone else's key", (r) => r.attackKeyTheft()],
];

function renderLab() {
  const sealed = !!round?.view?.sealed;
  $("#lab").innerHTML = ATTACKS.map(([name], i) => `<button data-a="${i}" ${sealed ? "" : "disabled"}>${esc(name)}</button>`).join("");
  document.querySelectorAll<HTMLButtonElement>("#lab button").forEach((b) =>
    b.addEventListener("click", () => {
      if (!round) return;
      const [name, f] = ATTACKS[Number(b.dataset.a)];
      const o = f(round);
      const li = document.createElement("li");
      li.className = "fresh";
      li.innerHTML = `<b>${esc(name)}</b> → ${o.ok ? "accepted?!" : `refused: <span class="verdict">${esc(o.message)}</span>`}`;
      $("#lab-results").prepend(li);
    }),
  );
}

function renderAll() {
  renderGhosts();
  renderObserver();
  renderRecipient();
  renderAuditor();
  renderLab();
  updateButtons();
}

// ------------------------------------------------------------------------------------------------
// Live on Esmeralda
// ------------------------------------------------------------------------------------------------

function phase(r: LiveRound, now: number): string {
  if (!r.sealed) return now < r.joinDeadline ? "open" : "expired: refunds open";
  return now < r.claimDeadline ? "sealed: claims open" : "closed";
}

function renderLiveRound(r: LiveRound, now: number | null, meta?: { label: string; create_tx: string; joins: { tx: string; funded_from: string }[]; claims: { tx: string }[]; refunds: { tx: string }[] }): string {
  const tx = (id: string) => `<a href="${EXPLORER}/tx/${assertTx(id)}" target="_blank" rel="noopener" class="mono">${short(id)}</a>`;
  assertComponent(r.component);
  const key = /^[0-9a-f]{64}$/;
  r = { ...r, members: r.members.filter((m) => key.test(m)), spentTags: r.spentTags.filter((t) => key.test(t)) };
  const joins = meta?.joins.map((j) => `<li>${tx(j.tx)}<span class="no">from ${esc(j.funded_from)}</span></li>`).join("") ?? "";
  const claims = meta?.claims.map((c) => `<li>${tx(c.tx)}<span class="no">throwaway signer</span></li>`).join("") ?? "";
  const refunds = meta?.refunds.map((c) => `<li>${tx(c.tx)}<span class="no">refund</span></li>`).join("") ?? "";
  return `<div class="round-card">
    <h2>${esc(meta?.label ?? "round")}</h2>
    <a class="mono" href="${EXPLORER}/substate/${r.component}" target="_blank" rel="noopener">${short(r.component)}</a>
    <div class="round-grid">
      <div class="stat"><div class="k">phase</div><div class="v">${now === null ? "?" : esc(phase(r, now))}</div></div>
      <div class="stat"><div class="k">members</div><div class="v">${r.members.length} / ${r.size}</div></div>
      <div class="stat"><div class="k">claims</div><div class="v">${r.claims}</div></div>
      <div class="stat"><div class="k">refunds</div><div class="v">${r.refunds}</div></div>
      <div class="stat"><div class="k">gift</div><div class="v">${tari(r.gift)}</div></div>
      <div class="stat"><div class="k">vault</div><div class="v">${tari(r.vault)}</div></div>
    </div>
    <p class="note">Tag base H recomputed in your browser from the round id: ${r.tagBaseVerified ? "✔ matches the value the template stored" : "✘ mismatch"}.</p>
    <div class="cols">
      <div><h3>Member keys</h3><ul class="rows">${r.members.map((m, i) => `<li><span class="mono">#${i} ${short(m)}</span></li>`).join("")}</ul>
        ${joins ? `<h3>Join transactions</h3><ul class="rows">${joins}</ul>` : ""}</div>
      <div><h3>Spent tags</h3><ul class="rows">${r.spentTags.map((t) => `<li><span class="mono">${short(t)}</span><span class="no">which member? unknown</span></li>`).join("") || `<li class="muted">none</li>`}</ul>
        ${claims ? `<h3>Claim transactions</h3><ul class="rows">${claims}</ul>` : ""}${refunds ? `<h3>Refund transactions</h3><ul class="rows">${refunds}</ul>` : ""}</div>
    </div>
  </div>`;
}

async function refreshLive() {
  const status = $("#live-status");
  const body = $("#live-body");
  status.textContent = "reading the public indexer…";
  const dep = await loadDeployment();
  const rounds = dep?.rounds ?? [];
  if (!rounds.length) {
    body.innerHTML = `<div class="banner empty">No live rounds have been recorded in this build yet.</div>`;
    status.textContent = "";
    return;
  }
  try {
    const now = await epoch();
    const live = await Promise.all(rounds.map((r) => fetchRound(r.component)));
    body.innerHTML =
      `<div class="banner live">Live from the Esmeralda indexer at consensus epoch ${Number(now)}${dep?.template && /^template_[0-9a-f]{64}$/.test(dep.template.address) ? ` · template <a href="${EXPLORER}/template/${dep.template.address.replace("template_", "")}" target="_blank" rel="noopener" class="mono">${short(dep.template.address)}</a>` : ""}</div>` +
      live.map((r, i) => renderLiveRound(r, now, rounds[i])).join("");
    status.textContent = "";
  } catch (e) {
    const snap = await loadSnapshot();
    if (!snap) {
      body.innerHTML = `<div class="banner recorded">The indexer is unreachable (${esc(String(e))}) and this build has no recorded snapshot.</div>`;
    } else {
      body.innerHTML =
        `<div class="banner recorded">Recorded data (taken ${esc(snap.taken_at)} at epoch ${snap.epoch}): the public indexer could not be reached just now.</div>` +
        snap.rounds.map((r) => renderLiveRound(r, snap.epoch, rounds.find((x) => x.component === r.component))).join("");
    }
    status.textContent = "";
  }
}

// ------------------------------------------------------------------------------------------------

function showTab(name: string) {
  document.querySelectorAll<HTMLButtonElement>(".tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll<HTMLElement>(".tab-panel").forEach((p) => p.classList.toggle("active", p.id === name));
  if (name === "live" && !$("#live-body").innerHTML) void refreshLive();
  history.replaceState(null, "", `#${name}`);
}

async function main() {
  document.querySelectorAll<HTMLButtonElement>(".tabs button").forEach((b) => b.addEventListener("click", () => showTab(b.dataset.tab!)));
  $("#run").addEventListener("click", () => void runAll());
  $("#step").addEventListener("click", () => stepOnce());
  $("#reset").addEventListener("click", () => reset());
  $("#live-refresh").addEventListener("click", () => void refreshLive());
  try {
    await loadWasm();
    $("#engine").textContent = "engine: poltergift.wasm (Rust ring signatures + the template's rules)";
  } catch (e) {
    log(`<span style="color:var(--red)">Could not load the WASM engine: ${esc(String(e))}</span>`);
    return;
  }
  reset();
  const hash = location.hash.replace("#", "");
  if (["summon", "live", "how"].includes(hash)) showTab(hash);
}

void main();
