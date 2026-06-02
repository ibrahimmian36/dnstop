/* main.js — entry point.
 *
 * Two modes:
 *   live (default)        yeet run main.js
 *   audit                 yeet run main.js -- --audit
 *                         add --duration N (seconds), --json
 *
 * One ringbuf in, one event kind out (a captured DNS query). state.js
 * parses and aggregates; dashboard.js draws live mode; audit.js prints
 * the one-shot report.
 */

import { RingBuf } from "yeet:bpf";
import bpf from "./bin/dnstop.bpf.o";

import { onEvent, advance, TICK_MS } from "./state.js";
import { renderDashboard, clearScreen } from "./dashboard.js";
import { runAudit } from "./audit.js";

const HIDE = "\x1b[?25l";
const SHOW = "\x1b[?25h";

const args = globalThis.yeet?.args ?? {};
const AUDIT_MODE = !!args.audit;
const AUDIT_JSON = !!args.json;

function parseDuration() {
  const raw = args.duration;
  if (raw == null) return 60;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return 60;
  return Math.min(3600, Math.floor(n));
}
const AUDIT_DURATION_MS = parseDuration() * 1000;

const tty = globalThis.tty;
if (!AUDIT_MODE && !tty) {
  console.error("dnstop: no tty available (yeet didn't expose globalThis.tty)");
  throw new Error("missing tty");
}

let cols = 100, rows = 36;
function readSize() {
  if (!tty) return;
  const sz = tty.size?.();
  if (sz) { cols = sz.cols ?? cols; rows = sz.rows ?? rows; }
}
readSize();
tty?.on?.("resize", () => { readSize(); paint(); });

function paint() {
  if (!tty) return;
  const frame = renderDashboard(cols, rows);
  if (tty.beginFrame) {
    tty.beginFrame();
    tty.write(frame);
    tty.endFrame();
  } else {
    tty.write(frame);
  }
}

async function main() {
  const control = await bpf
    .bind("events", { kind: "ringbuf", btf_struct: "dns_evt" })
    .start();

  await new RingBuf(control, "events").subscribe(
    (evt) => onEvent(evt.dns_evt ?? evt),
    (err) => console.error("dnstop ringbuf error:", err?.message ?? err),
  );

  if (AUDIT_MODE) {
    await runAudit({ durationMs: AUDIT_DURATION_MS, asJSON: AUDIT_JSON });
    return;
  }

  tty.write(HIDE);
  tty.write(clearScreen());
  setInterval(() => { advance(); paint(); }, TICK_MS);
  paint();
}

main().catch((e) => {
  tty?.write(SHOW);
  console.error(e?.stack ?? e?.message ?? e);
});
