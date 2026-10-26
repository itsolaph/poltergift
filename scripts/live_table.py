#!/usr/bin/env python3
"""Renders the README's "Live on Esmeralda" section from deployments/esmeralda.json.

    python3 scripts/live_table.py > /tmp/live.md
"""
import json
import sys
from pathlib import Path

EXPLORER = "https://explorer.tari.mw"
record = json.loads((Path(__file__).resolve().parent.parent / "deployments" / "esmeralda.json").read_text())


def tx(t):
    return f"[`{t[:10]}…`]({EXPLORER}/tx/{t})"


def comp(c):
    return f"[`{c[:18]}…`]({EXPLORER}/substate/{c})"


out = []
t = record["template"]
out.append("| what | address / transaction |")
out.append("|---|---|")
out.append(f"| template ({t['wasm_bytes']:,} bytes, blake2b `{t['wasm_blake2b_256'][:16]}…`) | "
           f"[`{t['address'][:22]}…`]({EXPLORER}/template/{t['address'].removeprefix('template_')}) · publish {tx(t['publish_tx'])} |")
for s in record.get("setup", []):
    out.append(f"| {s['kind']} | {tx(s['tx'])} |")
out.append("")
for r in record["rounds"]:
    p = r["params"]
    out.append(f"**{r['label']}**: {comp(r['component'])}, {p['size']} members × "
               f"{p['gift_amount_utari'] / 1e6:g} tTARI, claim fee {p['claim_fee_utari'] / 1e6:g} tTARI, "
               f"joins close at epoch {p['join_deadline_epoch']}, claims at epoch {p['claim_deadline_epoch']}.")
    out.append("")
    out.append("| step | transaction | public detail |")
    out.append("|---|---|---|")
    out.append(f"| create | {tx(r['create_tx'])} | |")
    for j in r["joins"]:
        out.append(f"| join | {tx(j['tx'])} | member key `{j['member_key'][:12]}…`, gift from a {j['funded_from']} output |")
    for c in r["claims"]:
        out.append(f"| claim | {tx(c['tx'])} | tag `{c['key_image'][:12]}…` → fresh output `{c['payout_output'][:12]}…` |")
    for c in r.get("refunds", []):
        out.append(f"| refund | {tx(c['tx'])} | tag `{c['key_image'][:12]}…` → fresh output `{c['payout_output'][:12]}…` |")
    out.append("")
sys.stdout.write("\n".join(out))
