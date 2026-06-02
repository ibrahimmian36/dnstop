/* Application state for dnstop.
 *
 * BPF ships one event per outbound DNS query (raw packet bytes). We
 * parse each in dns_parser, aggregate per-process and per-registrable-
 * domain, and run two detectors:
 *
 *   DGA-like:    one process emitting many high-entropy lookups across
 *                many distinct registrable domains. Classic domain-
 *                generation-algorithm fishing for a live C2.
 *   Tunnel-like: many unique subdomains under a single registrable
 *                domain, with long encoded labels. Classic DNS
 *                tunneling / exfiltration.
 *
 * These are near-opposite on the registrable-domain axis (DGA spreads
 * across domains, tunneling concentrates under one), so they don't
 * trip each other.
 */

import { parseDNS, qtypeName, querySignals } from "./dns_parser.js";

export const TICK_MS   = 200;
export const HIST_LEN  = 240;
const PROC_STALE_MS    = 120_000;
const DOM_STALE_MS     = 120_000;
const FEED_KEEP        = 200;

/* ---- detection thresholds ----------------------------------------- */
/* A query counts as "high entropy" only if it's both random-looking
 * and long enough that the entropy is meaningful (short names have
 * unstable entropy). */
const HIGH_ENTROPY_BITS   = 3.5;
const HIGH_ENTROPY_MINLEN = 10;

/* DGA: a process needs this many high-entropy queries across this many
 * distinct registrable domains, and at least this fraction of its
 * queries high-entropy, before it trips. */
const DGA_MIN_HE_QUERIES  = 8;
const DGA_MIN_DOMAINS     = 8;
const DGA_MIN_HE_FRACTION = 0.5;

/* Tunneling: a registrable domain needs this many unique subdomains
 * and a max label at least this long (data encoded into labels). */
const TUNNEL_MIN_SUBDOMAINS = 20;
const TUNNEL_MIN_LABEL      = 40;

/* ---- global counters + history ------------------------------------ */
export const startTime = Date.now();
export const tot = {
  events: 0,
  queries: 0,
  parse_fail: 0,
  responses: 0,
};

let tickQueries = 0;
export const queryHist = [];
function pushHist(arr, v) { arr.push(v); if (arr.length > HIST_LEN) arr.shift(); }

/* ---- anonymize ---------------------------------------------------- */
const anon = !!globalThis.yeet?.args?.anonymize;
const aliasMaps = { name: new Map(), dom: new Map() };
function aliasGen(kind, key, prefix) {
  const m = aliasMaps[kind];
  let a = m.get(key);
  if (!a) { a = prefix + String(m.size + 1).padStart(2, "0"); m.set(key, a); }
  return a;
}
export function aName(s) { return anon && s ? aliasGen("name", s, "proc-") : s; }
export function aDom(s)  { return anon && s ? aliasGen("dom", s, "domain-") : s; }

/* ---- aggregators -------------------------------------------------- */
/* ProcStat keyed by "pid\x00comm". */
const procs = new Map();
/* DomStat keyed by registrable domain string. */
const domains = new Map();
/* CommAgg keyed by comm alone, aggregating DGA signals across PIDs.
 * Catches fork-per-query DGA: malware (or a script) that spawns a
 * fresh short-lived process per lookup, so no single PID crosses the
 * threshold but the comm collectively does. */
const commAggs = new Map();

function num(v) { return typeof v === "bigint" ? Number(v) : v; }
function procKey(pid, comm) { return pid + "\x00" + comm; }

function getProc(pid, comm) {
  const key = procKey(pid, comm);
  let p = procs.get(key);
  if (!p) {
    p = {
      pid, comm,
      queries: 0,
      he_queries: 0,                 /* high-entropy query count       */
      nx_responses: 0,               /* reserved for response tracking */
      entropy_sum: 0,                /* for running average            */
      domains: new Set(),            /* distinct registrable domains   */
      qtypes: new Map(),             /* qtype number → count           */
      max_label_seen: 0,
      rate_hist: [],
      first_seen: Date.now(),
      last_seen:  Date.now(),
      _lastQ: 0,
    };
    procs.set(key, p);
  }
  return p;
}

function getDomain(reg) {
  let d = domains.get(reg);
  if (!d) {
    d = {
      registrable: reg,
      queries: 0,
      subdomains: new Set(),         /* distinct full qnames under it  */
      max_label_seen: 0,
      txt_queries: 0,
      procs: new Set(),
      first_seen: Date.now(),
      last_seen:  Date.now(),
    };
    domains.set(reg, d);
  }
  return d;
}

function getCommAgg(comm) {
  let c = commAggs.get(comm);
  if (!c) {
    c = {
      comm,
      queries: 0,
      he_queries: 0,
      domains: new Set(),            /* distinct registrable domains   */
      pids: new Set(),               /* distinct pids under this comm  */
      last_seen: Date.now(),
    };
    commAggs.set(comm, c);
  }
  return c;
}

/* ---- live feed ---------------------------------------------------- */
const feed = [];
function pushFeed(rec) { feed.push(rec); if (feed.length > FEED_KEEP) feed.shift(); }

/* ---- ingest ------------------------------------------------------- */
export function onEvent(e) {
  if (!e) return;
  tot.events++;
  const now = Date.now();

  const pid  = num(e.pid) | 0;
  const comm = String(e.comm || "?");
  const proto = num(e.proto) | 0;
  const plen  = num(e.payload_len) | 0;

  /* Normalize payload to Uint8Array. */
  let payload;
  if (e.payload instanceof Uint8Array) {
    payload = e.payload;
  } else if (e.payload && typeof e.payload.length === "number") {
    payload = new Uint8Array(e.payload.length);
    for (let i = 0; i < e.payload.length; i++) payload[i] = e.payload[i] | 0;
  } else {
    return;
  }

  if (plen === 0) { tot.parse_fail++; return; }

  const dns = parseDNS(payload, plen);
  if (!dns.valid) { tot.parse_fail++; return; }

  /* Responses (QR=1) are reserved for future NXDOMAIN tracking. For
   * now we count them and move on; query-side detection is the v1
   * scope. */
  if (!dns.is_query) { tot.responses++; return; }

  tot.queries++; tickQueries++;

  const sig = querySignals(dns.qname);
  const isHighEntropy = sig.entropy >= HIGH_ENTROPY_BITS &&
                        sig.total_len >= HIGH_ENTROPY_MINLEN;

  /* per-process */
  const p = getProc(pid, comm);
  p.queries++;
  p.entropy_sum += sig.entropy;
  p.domains.add(sig.registrable);
  p.qtypes.set(dns.qtype, (p.qtypes.get(dns.qtype) || 0) + 1);
  if (sig.max_label > p.max_label_seen) p.max_label_seen = sig.max_label;
  if (isHighEntropy) p.he_queries++;
  p.last_seen = now;

  /* per-comm aggregate (across PIDs) for fork-per-query DGA */
  const ca = getCommAgg(comm);
  ca.queries++;
  ca.domains.add(sig.registrable);
  ca.pids.add(pid);
  if (isHighEntropy) ca.he_queries++;
  ca.last_seen = now;

  /* per-registrable-domain */
  const d = getDomain(sig.registrable);
  d.queries++;
  d.subdomains.add(dns.qname);
  if (sig.max_label > d.max_label_seen) d.max_label_seen = sig.max_label;
  if (dns.qtype === 16) d.txt_queries++;     /* TXT */
  d.procs.add(procKey(pid, comm));
  d.last_seen = now;

  pushFeed({
    ts: now, pid, comm,
    qname: dns.qname,
    qtype: dns.qtype,
    qtype_name: qtypeName(dns.qtype),
    proto,
    entropy: sig.entropy,
    high_entropy: isHighEntropy,
    registrable: sig.registrable,
  });
}

/* ---- per-tick advance + reaping ----------------------------------- */
export function advance() {
  const now = Date.now();
  pushHist(queryHist, tickQueries); tickQueries = 0;

  for (const p of procs.values()) {
    const last = p._lastQ ?? p.queries;
    pushHist(p.rate_hist, p.queries - last);
    p._lastQ = p.queries;
  }

  for (const [k, p] of procs) if (now - p.last_seen > PROC_STALE_MS) procs.delete(k);
  for (const [k, d] of domains) if (now - d.last_seen > DOM_STALE_MS) domains.delete(k);
  for (const [k, c] of commAggs) if (now - c.last_seen > PROC_STALE_MS) commAggs.delete(k);
  while (feed.length && now - feed[0].ts > 120_000) feed.shift();
}

/* ---- detection ---------------------------------------------------- */
/* Returns "dga" if a process looks like it's running a domain-
 * generation algorithm, else null. */
function procDGAVerdict(p) {
  if (p.he_queries < DGA_MIN_HE_QUERIES) return null;
  if (p.domains.size < DGA_MIN_DOMAINS) return null;
  if (p.queries === 0) return null;
  if (p.he_queries / p.queries < DGA_MIN_HE_FRACTION) return null;
  return "dga";
}

/* Returns "tunnel" if a registrable domain looks like a tunnel, else
 * null. */
function domainTunnelVerdict(d) {
  if (d.subdomains.size < TUNNEL_MIN_SUBDOMAINS) return null;
  if (d.max_label_seen < TUNNEL_MIN_LABEL) return null;
  return "tunnel";
}

/* Comm-level DGA verdict (across PIDs). Same thresholds as per-PID. */
function commDGAVerdict(c) {
  if (c.he_queries < DGA_MIN_HE_QUERIES) return null;
  if (c.domains.size < DGA_MIN_DOMAINS) return null;
  if (c.queries === 0) return null;
  if (c.he_queries / c.queries < DGA_MIN_HE_FRACTION) return null;
  return "dga";
}

/* True if some individual PID under this comm already trips the per-PID
 * DGA verdict. Used to avoid double-reporting: a single-process DGA is
 * already covered by its per-PID alert, so we only surface a comm-level
 * alert when NO single PID trips but the comm collectively does (the
 * fork-per-query pattern). */
function commHasPidLevelDGA(comm) {
  for (const p of procs.values()) {
    if (p.comm === comm && procDGAVerdict(p)) return true;
  }
  return false;
}

/* Comm-level DGA alerts: comm trips, but spread across multiple PIDs
 * with no single PID tripping. */
function listCommDGA() {
  const out = [];
  for (const c of commAggs.values()) {
    if (!commDGAVerdict(c)) continue;
    if (c.pids.size < 2) continue;            /* single PID → per-PID covers it */
    if (commHasPidLevelDGA(c.comm)) continue; /* already reported per-PID */
    out.push({
      comm: c.comm,
      he_queries: c.he_queries,
      unique_domains: c.domains.size,
      queries: c.queries,
      pid_count: c.pids.size,
      last_seen: c.last_seen,
    });
  }
  return out;
}

/* ---- accessors ---------------------------------------------------- */
const oneSecTicks = Math.max(1, Math.round(1000 / TICK_MS));
function sumTail(arr, n) {
  const start = Math.max(0, arr.length - n);
  let s = 0;
  for (let i = start; i < arr.length; i++) s += arr[i];
  return s;
}

export function liveRates() {
  return {
    queries_per_sec: sumTail(queryHist, oneSecTicks),
    procs: procs.size,
    domains: domains.size,
  };
}

export function listProcs(n) {
  const out = [];
  for (const p of procs.values()) {
    const rate = sumTail(p.rate_hist, oneSecTicks);
    out.push({
      p,
      rate,
      avg_entropy: p.queries ? p.entropy_sum / p.queries : 0,
      unique_domains: p.domains.size,
      dga: procDGAVerdict(p),
    });
  }
  /* DGA-flagged first, then by query rate. */
  out.sort((a, b) => {
    if ((a.dga ? 1 : 0) !== (b.dga ? 1 : 0)) return a.dga ? -1 : 1;
    return b.rate - a.rate;
  });
  return out.slice(0, n);
}

export function listDomains(n) {
  const out = [];
  for (const d of domains.values()) {
    out.push({
      d,
      unique_subdomains: d.subdomains.size,
      tunnel: domainTunnelVerdict(d),
    });
  }
  out.sort((a, b) => {
    if ((a.tunnel ? 1 : 0) !== (b.tunnel ? 1 : 0)) return a.tunnel ? -1 : 1;
    return b.d.queries - a.d.queries;
  });
  return out.slice(0, n);
}

export function listAlerts(n) {
  const out = [];
  for (const p of procs.values()) {
    if (procDGAVerdict(p)) {
      out.push({
        kind: "dga",
        pid: p.pid, comm: p.comm,
        he_queries: p.he_queries,
        unique_domains: p.domains.size,
        queries: p.queries,
        last_seen: p.last_seen,
      });
    }
  }
  for (const cd of listCommDGA()) {
    out.push({
      kind: "dga_comm",
      comm: cd.comm,
      he_queries: cd.he_queries,
      unique_domains: cd.unique_domains,
      queries: cd.queries,
      pid_count: cd.pid_count,
      last_seen: cd.last_seen,
    });
  }
  for (const d of domains.values()) {
    if (domainTunnelVerdict(d)) {
      out.push({
        kind: "tunnel",
        registrable: d.registrable,
        unique_subdomains: d.subdomains.size,
        max_label: d.max_label_seen,
        txt_queries: d.txt_queries,
        queries: d.queries,
        last_seen: d.last_seen,
      });
    }
  }
  out.sort((a, b) => b.last_seen - a.last_seen);
  return out.slice(0, n);
}

export function recentQueries(n) { return feed.slice(-n).reverse(); }

export function counts() {
  let dga = 0, tunnel = 0;
  for (const p of procs.values()) if (procDGAVerdict(p)) dga++;
  dga += listCommDGA().length;
  for (const d of domains.values()) if (domainTunnelVerdict(d)) tunnel++;
  return {
    procs: procs.size,
    domains: domains.size,
    dga_alerts: dga,
    tunnel_alerts: tunnel,
  };
}

/* ---- audit snapshot ----------------------------------------------- */
export function auditSnapshot() {
  const now = Date.now();

  const procList = [];
  for (const p of procs.values()) {
    procList.push({
      pid: p.pid, comm: p.comm,
      queries: p.queries,
      he_queries: p.he_queries,
      unique_domains: p.domains.size,
      avg_entropy: p.queries ? p.entropy_sum / p.queries : 0,
      max_label: p.max_label_seen,
      dga: procDGAVerdict(p),
      first_seen: p.first_seen, last_seen: p.last_seen,
    });
  }
  procList.sort((a, b) => b.queries - a.queries);

  const domList = [];
  for (const d of domains.values()) {
    domList.push({
      registrable: d.registrable,
      queries: d.queries,
      unique_subdomains: d.subdomains.size,
      max_label: d.max_label_seen,
      txt_queries: d.txt_queries,
      proc_count: d.procs.size,
      tunnel: domainTunnelVerdict(d),
    });
  }
  domList.sort((a, b) => b.queries - a.queries);

  const dgaProcs = procList.filter((p) => p.dga);
  const commDGA = listCommDGA();
  const tunnelDoms = domList.filter((d) => d.tunnel);

  let verdict;
  const anyDGA = dgaProcs.length > 0 || commDGA.length > 0;
  if (anyDGA && tunnelDoms.length > 0) verdict = "CRITICAL";
  else if (anyDGA) verdict = "DGA";
  else if (tunnelDoms.length > 0) verdict = "TUNNEL";
  else verdict = "CLEAN";

  return {
    scan_duration_ms: now - startTime,
    started_at: startTime,
    total_events: tot.events,
    total_queries: tot.queries,
    parse_fail: tot.parse_fail,
    responses: tot.responses,
    distinct_procs: procs.size,
    distinct_domains: domains.size,
    procs: procList,
    domains: domList,
    dga_procs: dgaProcs,
    dga_comms: commDGA,
    tunnel_domains: tunnelDoms,
    top_domains: domList.slice(0, 20),
    verdict,
  };
}
