/* audit.js — one-shot DNS scan + report.
 *
 * Runs for a fixed window, then prints a verdict and supporting
 * evidence. Human (default) or JSON (--json). Scrolling output, safe
 * to pipe or redirect.
 */

import { auditSnapshot, advance } from "./state.js";
import {
  fg, bold, ital, RESET,
  C_ALERT, C_DGA, C_TUNNEL, C_HIGHE, C_OK, C_DIM, C_NORMAL,
  fmtDuration, compactNum,
} from "./render.js";

function startAdvanceTicker(intervalMs) {
  return setInterval(() => { try { advance(); } catch (_) {} }, intervalMs);
}

function banner() {
  return [
    "════════════════════════════════════════════════════════════════",
    "  dnstop audit · DNS query behavior scan",
    "════════════════════════════════════════════════════════════════",
  ].join("\n");
}

function timestamp() {
  return new Date().toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

function verdictLine(v, snap) {
  const dgaCount = snap.dga_procs.length + (snap.dga_comms ? snap.dga_comms.length : 0);
  switch (v) {
    case "CRITICAL":
      return bold + fg(C_ALERT) + "VERDICT: CRITICAL — DGA and tunneling both detected" + RESET +
             "\n  " + fg(C_ALERT) + dgaCount + " process group(s) DGA-like, " +
             snap.tunnel_domains.length + " domain(s) tunnel-like." + RESET;
    case "DGA":
      return bold + fg(C_DGA) + "VERDICT: DGA-LIKE ACTIVITY DETECTED" + RESET +
             "\n  " + fg(C_DGA) + dgaCount +
             " process group(s) emitting many high-entropy lookups across many domains." + RESET;
    case "TUNNEL":
      return bold + fg(C_TUNNEL) + "VERDICT: DNS TUNNELING SUSPECTED" + RESET +
             "\n  " + fg(C_TUNNEL) + snap.tunnel_domains.length +
             " domain(s) with many long-label subdomains." + RESET;
    case "CLEAN":
    default:
      return bold + fg(C_OK) + "VERDICT: NO DGA OR TUNNELING DETECTED" + RESET +
             "\n  " + fg(C_OK) +
             "No high-entropy domain fishing. No long-label subdomain floods." + RESET;
  }
}

export function printHumanReport(snap) {
  const L = [];
  L.push(banner());
  L.push("");
  L.push("  Scan started: " + new Date(snap.started_at).toISOString());
  L.push("  Scan ended:   " + timestamp());
  L.push("  Duration:     " + fmtDuration(snap.scan_duration_ms));
  L.push("");

  L.push(fg(C_DIM) + "── Queries observed ────────────────────────────────────────────" + RESET);
  L.push("  DNS queries seen:       " + snap.total_queries);
  L.push("  Distinct processes:     " + snap.distinct_procs);
  L.push("  Distinct domains:       " + snap.distinct_domains);
  L.push("  Unparseable payloads:   " + snap.parse_fail);
  L.push("");

  L.push(fg(C_DIM) + "── DGA detection ───────────────────────────────────────────────" + RESET);
  const commDGA = snap.dga_comms || [];
  if (snap.dga_procs.length === 0 && commDGA.length === 0) {
    L.push("  " + fg(C_OK) + "✓ no DGA-like processes" + RESET);
  } else {
    for (const p of snap.dga_procs) {
      L.push("  " + fg(C_DGA) + bold + "⚠ pid " + p.pid + " (" + p.comm + ")" + RESET);
      L.push("    " + p.he_queries + " high-entropy lookups across " +
             p.unique_domains + " domains (avg entropy " + p.avg_entropy.toFixed(2) + ")");
    }
    for (const c of commDGA) {
      L.push("  " + fg(C_DGA) + bold + "⚠ " + c.comm + " ×" + c.pid_count + " processes" + RESET);
      L.push("    " + c.he_queries + " high-entropy lookups across " +
             c.unique_domains + " domains (fork-per-query pattern)");
    }
  }
  L.push("");

  L.push(fg(C_DIM) + "── Tunneling detection ─────────────────────────────────────────" + RESET);
  if (snap.tunnel_domains.length === 0) {
    L.push("  " + fg(C_OK) + "✓ no tunnel-like domains" + RESET);
  } else {
    for (const d of snap.tunnel_domains) {
      L.push("  " + fg(C_TUNNEL) + bold + "⚠ " + d.registrable + RESET);
      L.push("    " + d.unique_subdomains + " unique subdomains, max label " +
             d.max_label + (d.txt_queries > 0 ? ", " + d.txt_queries + " TXT" : ""));
    }
  }
  L.push("");

  if (snap.top_domains.length > 0) {
    L.push(fg(C_DIM) + "── Top domains by query volume ─────────────────────────────────" + RESET);
    const max = Math.min(10, snap.top_domains.length);
    for (let i = 0; i < max; i++) {
      const d = snap.top_domains[i];
      const tag = d.tunnel ? fg(C_TUNNEL) + " [TUNNEL]" + RESET : "";
      L.push("  " + String(i + 1).padStart(2) + ". " + d.registrable +
             fg(C_DIM) + "  " + d.queries + " queries, " + d.unique_subdomains + " subdomains" + RESET + tag);
    }
    L.push("");
  } else if (snap.total_queries === 0) {
    L.push(fg(C_DIM) + ital + "  (no DNS queries observed during the scan window)" + RESET);
    L.push("");
  }

  L.push("════════════════════════════════════════════════════════════════");
  L.push(verdictLine(snap.verdict, snap));
  L.push("════════════════════════════════════════════════════════════════");
  return L.join("\n") + "\n";
}

export function printJSONReport(snap) {
  const safe = {
    dnstop_audit_version: 1,
    scan_started_at: new Date(snap.started_at).toISOString(),
    scan_duration_ms: snap.scan_duration_ms,
    verdict: snap.verdict,
    total_queries: snap.total_queries,
    distinct_procs: snap.distinct_procs,
    distinct_domains: snap.distinct_domains,
    parse_fail: snap.parse_fail,
    responses: snap.responses,
    dga_procs: snap.dga_procs.map((p) => ({
      pid: p.pid, comm: p.comm,
      queries: p.queries,
      high_entropy_queries: p.he_queries,
      unique_domains: p.unique_domains,
      avg_entropy: Number(p.avg_entropy.toFixed(3)),
      max_label: p.max_label,
    })),
    dga_comms: (snap.dga_comms || []).map((c) => ({
      comm: c.comm,
      pid_count: c.pid_count,
      queries: c.queries,
      high_entropy_queries: c.he_queries,
      unique_domains: c.unique_domains,
      pattern: "fork-per-query",
    })),
    tunnel_domains: snap.tunnel_domains.map((d) => ({
      registrable: d.registrable,
      queries: d.queries,
      unique_subdomains: d.unique_subdomains,
      max_label: d.max_label,
      txt_queries: d.txt_queries,
    })),
    top_domains: snap.top_domains.map((d) => ({
      registrable: d.registrable,
      queries: d.queries,
      unique_subdomains: d.unique_subdomains,
      max_label: d.max_label,
      tunnel: !!d.tunnel,
    })),
  };
  return JSON.stringify(safe, null, 2) + "\n";
}

export function runAudit(opts) {
  opts = opts || {};
  const durationMs = opts.durationMs || 60_000;
  const asJSON = !!opts.asJSON;
  const write = opts.write || ((s) => {
    if (globalThis.tty?.write) globalThis.tty.write(s);
    else process.stdout.write(s);
  });
  const onComplete = opts.onComplete;

  if (!asJSON) {
    write(banner() + "\n");
    write("  Watching DNS queries for " + fmtDuration(durationMs) + "...\n");
    write("  " + fg(C_DIM) + ital + "(quiet during scan, full report at the end)" + RESET + "\n\n");
  }

  const ticker = startAdvanceTicker(200);

  return new Promise((resolve) => {
    setTimeout(() => {
      clearInterval(ticker);
      const snap = auditSnapshot();
      write(asJSON ? printJSONReport(snap) : printHumanReport(snap));
      resolve(snap);
      if (onComplete) onComplete(snap);
    }, durationMs);
  });
}
