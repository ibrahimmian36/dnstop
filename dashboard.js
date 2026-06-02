/* Dashboard composition for dnstop. Same layout idioms as the rest of
 * the family (xtop / blktop / minertop / ...), with DNS-specific panels.
 *
 * Panel order:
 *   DNS ALERTS    only shown when DGA or tunnel detections exist; lead
 *                 panel, red border, the reason the tool exists
 *   PROCESSES     top query sources, with rate, unique domains, entropy
 *   DOMAINS       top registrable domains by query volume
 *   QUERY FEED    live queries, newest first
 */

import {
  fg, bold, dim, ital, RESET, EOL,
  C_AXIS, C_DIM, C_ALERT, C_DGA, C_TUNNEL, C_HIGHE, C_NORMAL, C_OK, C_QUERY,
  entropyColor, queryMark,
  formatBytes, compactNum, mmss, fmtDuration,
  vlen, clipAnsi, fixw, padVis,
  sparkline,
} from "./render.js";

import {
  tot, queryHist,
  liveRates, listProcs, listDomains, listAlerts, recentQueries, counts,
  aName, aDom, startTime,
  TICK_MS,
} from "./state.js";

const MIN_COLS = 80;
const MIN_ROWS = 28;

/* ---- chrome helpers ----------------------------------------------- */
function topRule(C, title) {
  const head = ` ▌ ${title} `;
  return bold + fg(C_QUERY) + head + RESET + fg(C_AXIS) +
    "─".repeat(Math.max(0, C - head.length)) + RESET + EOL;
}
function botRule(C) { return fg(C_AXIS) + "─".repeat(C) + RESET + EOL; }
function sectionBar(C, text, accent = 45) {
  const prefix = fg(accent) + "  " + text + " ";
  const tail = fg(C_AXIS) + "─".repeat(Math.max(0, C - vlen(prefix))) + RESET;
  return clipAnsi(prefix + tail, C) + EOL;
}
function alertBar(C, text) {
  const prefix = bold + fg(C_ALERT) + "  ⚠ " + text + " " + RESET;
  const tail = fg(C_ALERT) + "─".repeat(Math.max(0, C - vlen(prefix))) + RESET;
  return clipAnsi(prefix + tail, C) + EOL;
}

/* ---- header ------------------------------------------------------- */
function headerLine(C) {
  const r = liveRates();
  const c = counts();
  const live = bold + fg(46) + "●" + RESET + fg(252) + " LIVE " + RESET;
  const up = fg(C_DIM) + mmss(Date.now() - startTime) + RESET;
  const qps = fg(C_QUERY) + compactNum(r.queries_per_sec) + RESET + fg(C_DIM) + " q/s" + RESET;
  const procs = fg(252) + compactNum(r.procs) + RESET + fg(C_DIM) + " procs" + RESET;
  const doms = fg(252) + compactNum(r.domains) + RESET + fg(C_DIM) + " domains" + RESET;

  let alertCell;
  if (c.dga_alerts > 0 || c.tunnel_alerts > 0) {
    const bits = [];
    if (c.dga_alerts > 0) bits.push(fg(C_DGA) + c.dga_alerts + " DGA" + RESET);
    if (c.tunnel_alerts > 0) bits.push(fg(C_TUNNEL) + c.tunnel_alerts + " tunnel" + RESET);
    alertCell = bold + fg(C_ALERT) + "⚠ " + RESET + bits.join(fg(C_DIM) + " · " + RESET);
  } else {
    alertCell = fg(C_OK) + "✓ no alerts" + RESET;
  }

  const left = `${live}${up}   ${qps}   ${procs}   ${doms}`;
  const right = alertCell;
  const pad = Math.max(1, C - vlen(left) - vlen(right));
  return left + " ".repeat(pad) + right + EOL;
}

/* ---- ALERTS panel ------------------------------------------------- */
function panelAlerts(C, H) {
  const list = listAlerts(H);
  const out = [];
  for (const a of list) {
    if (out.length >= H) break;
    if (a.kind === "dga") {
      const tag = bold + fg(C_DGA) + "DGA   " + RESET;
      const who = fg(C_DGA) + fixw(aName(a.comm), 18) + RESET +
                  fg(C_DIM) + " pid " + fixw(String(a.pid), 7) + RESET;
      const detail = fg(252) + a.he_queries + " high-entropy lookups across " +
                     a.unique_domains + " domains" + RESET;
      out.push(clipAnsi("  " + tag + who + detail, C));
    } else if (a.kind === "dga_comm") {
      const tag = bold + fg(C_DGA) + "DGA   " + RESET;
      const who = fg(C_DGA) + fixw(aName(a.comm), 18) + RESET +
                  fg(C_DIM) + " ×" + fixw(String(a.pid_count) + " pids", 9) + RESET;
      const detail = fg(252) + a.he_queries + " high-entropy lookups across " +
                     a.unique_domains + " domains (fork-per-query)" + RESET;
      out.push(clipAnsi("  " + tag + who + detail, C));
    } else {
      const tag = bold + fg(C_TUNNEL) + "TUNNEL" + RESET;
      const who = fg(C_TUNNEL) + " " + fixw(aDom(a.registrable), 28) + RESET;
      const detail = fg(252) + a.unique_subdomains + " unique subdomains · max label " +
                     a.max_label + (a.txt_queries > 0 ? " · " + a.txt_queries + " TXT" : "") + RESET;
      out.push(clipAnsi("  " + tag + who + detail, C));
    }
  }
  while (out.length < H) out.push(" ".repeat(C));
  return out;
}

/* ---- PROCESSES panel ---------------------------------------------- */
function panelProcs(C, H) {
  const list = listProcs(H);
  if (list.length === 0) {
    const msg = [fg(C_DIM) + ital + "  no DNS queries observed yet." + RESET];
    while (msg.length < H) msg.push(" ".repeat(C));
    return msg;
  }
  const out = [];
  let maxRate = 1;
  for (const it of list) if (it.rate > maxRate) maxRate = it.rate;

  for (const it of list) {
    if (out.length >= H) break;
    const p = it.p;
    const flagged = it.dga === "dga";
    const color = flagged ? C_DGA : C_NORMAL;
    const mark = flagged ? bold + fg(C_DGA) + "⚠" + RESET : fg(C_DIM) + "·" + RESET;
    const name = fg(color) + fixw(aName(p.comm), 18) + RESET;
    const pid = fg(C_DIM) + "pid " + fixw(String(p.pid), 7) + RESET;
    const rate = fg(C_QUERY) + fixw(compactNum(it.rate) + " q/s", 9) + RESET;
    const uniq = fg(252) + fixw(it.unique_domains + " dom", 8) + RESET;
    const ent = fg(entropyColor(it.avg_entropy, it.avg_entropy >= 3.5)) +
                fixw("H " + it.avg_entropy.toFixed(2), 8) + RESET;
    const spark = sparkline(p.rate_hist, Math.max(0, Math.min(20, C - 64)), C_QUERY);
    out.push(clipAnsi(" " + mark + " " + name + " " + pid + " " + rate + " " + uniq + " " + ent + " " + spark, C));
  }
  while (out.length < H) out.push(" ".repeat(C));
  return out;
}

/* ---- DOMAINS panel ------------------------------------------------ */
function panelDomains(C, H) {
  const list = listDomains(H);
  if (list.length === 0) {
    const msg = [fg(C_DIM) + ital + "  no domains resolved yet." + RESET];
    while (msg.length < H) msg.push(" ".repeat(C));
    return msg;
  }
  const out = [];
  for (const it of list) {
    if (out.length >= H) break;
    const d = it.d;
    const flagged = it.tunnel === "tunnel";
    const color = flagged ? C_TUNNEL : C_NORMAL;
    const mark = flagged ? bold + fg(C_TUNNEL) + "⚠" + RESET : fg(C_DIM) + "·" + RESET;
    const name = fg(color) + fixw(aDom(d.registrable), 34) + RESET;
    const q = fg(252) + fixw(compactNum(d.queries) + " q", 8) + RESET;
    const subs = fg(C_DIM) + fixw(it.unique_subdomains + " sub", 9) + RESET;
    const lbl = fg(C_DIM) + fixw("lbl " + d.max_label_seen, 8) + RESET;
    out.push(clipAnsi(" " + mark + " " + name + " " + q + " " + subs + " " + lbl, C));
  }
  while (out.length < H) out.push(" ".repeat(C));
  return out;
}

/* ---- QUERY FEED panel --------------------------------------------- */
function panelFeed(C, H) {
  const list = recentQueries(H);
  const out = [];
  for (const rec of list) {
    if (out.length >= H) break;
    const ts = fg(C_DIM) + mmss(rec.ts - startTime) + RESET;
    const mk = rec.high_entropy ? bold + fg(C_HIGHE) + queryMark(rec) + RESET
                                : fg(C_DIM) + queryMark(rec) + RESET;
    const qt = fg(C_DIM) + fixw(rec.qtype_name, 6) + RESET;
    const name = fg(rec.high_entropy ? C_HIGHE : 252) + fixw(aDom(rec.qname), Math.max(20, C - 48)) + RESET;
    const who = fg(C_DIM) + fixw(aName(rec.comm), 14) + RESET;
    out.push(clipAnsi(" " + ts + " " + mk + " " + qt + " " + name + " " + who, C));
  }
  while (out.length < H) out.push(" ".repeat(C));
  return out;
}

/* ---- composition -------------------------------------------------- */
export function clearScreen() { return "\x1b[2J\x1b[H"; }

export function renderDashboard(C, R) {
  C = Math.max(MIN_COLS, C | 0);
  R = Math.max(MIN_ROWS, R | 0);
  const rows = [];
  const c = counts();
  const hasAlerts = (c.dga_alerts + c.tunnel_alerts) > 0;

  rows.push(topRule(C, "DNSTOP · DNS query observatory"));
  rows.push(headerLine(C));
  rows.push("");

  /* chrome:
   *   top + header + blank          = 3
   *   [alerts-title + body block]   variable
   *   procs-title + blank-before    = 2
   *   domains-title + blank-before  = 2
   *   feed-title + blank-before     = 2
   *   bottom-rule                   = 1
   */
  let chrome = 3 + 2 + 2 + 2 + 1;
  let alertH = 0;
  if (hasAlerts) {
    alertH = Math.min(6, Math.max(1, c.dga_alerts + c.tunnel_alerts));
    chrome += 1 + alertH;   /* alert title + body */
  }
  const content = R - chrome;
  const procsH = Math.max(3, Math.round(content * 0.34));
  const domsH  = Math.max(3, Math.round(content * 0.30));
  const feedH  = Math.max(3, content - procsH - domsH);

  if (hasAlerts) {
    rows.push(alertBar(C, "DNS ALERTS · DGA / tunneling detections"));
    const al = panelAlerts(C, alertH);
    for (let i = 0; i < alertH; i++) rows.push(al[i] ?? " ".repeat(C));
    rows.push("");
  }

  rows.push(sectionBar(C, "PROCESSES · query sources (⚠ DGA-flagged) · rate · unique domains · avg entropy"));
  const px = panelProcs(C, procsH);
  for (let i = 0; i < procsH; i++) rows.push(px[i] ?? " ".repeat(C));

  rows.push("");
  rows.push(sectionBar(C, "DOMAINS · registrable domains by query volume (⚠ tunnel-flagged)"));
  const dx = panelDomains(C, domsH);
  for (let i = 0; i < domsH; i++) rows.push(dx[i] ?? " ".repeat(C));

  rows.push("");
  rows.push(sectionBar(C, "QUERY FEED · newest first · ⚠ high-entropy name · T TXT"));
  const fx = panelFeed(C, feedH);
  for (let i = 0; i < feedH; i++) rows.push(fx[i] ?? " ".repeat(C));

  rows.push(botRule(C));

  /* Pad/truncate to exactly R lines. */
  while (rows.length < R) rows.push(" ".repeat(C) + EOL);
  return "\x1b[H" + rows.slice(0, R).join("\n");
}
