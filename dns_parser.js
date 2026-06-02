/* DNS wire-format parser and detection signals.
 *
 * The BPF side ships raw DNS packet bytes. Here we decode the header
 * and question section, then compute the signals the dashboard and
 * audit verdict rely on: name entropy (DGA), label/name length
 * (tunneling), query type, digit ratio.
 *
 * We parse only what we need. The question section is enough for
 * query-side detection; we read the header flags so response packets
 * (QR=1) can be told apart and their RCODE (NXDOMAIN) read.
 */

/* QTYPE numbers we care to name. Others render as "TYPE<n>". */
const QTYPE_NAMES = {
  1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
  16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 43: "DS",
  46: "RRSIG", 48: "DNSKEY", 65: "HTTPS", 64: "SVCB", 10: "NULL",
  17: "RP", 99: "SPF", 251: "IXFR", 252: "AXFR", 255: "ANY",
};

export function qtypeName(n) {
  return QTYPE_NAMES[n] || ("TYPE" + n);
}

/* RCODE 3 == NXDOMAIN. */
export const RCODE_NXDOMAIN = 3;

/* Parse a DNS message from a Uint8Array. Returns:
 *   { valid:true, id, is_query, opcode, rcode, truncated,
 *     qdcount, ancount, nscount, arcount,
 *     qname, qtype, qclass }   (first question only)
 * or { valid:false, reason } if the bytes don't look like DNS. */
export function parseDNS(buf, len) {
  const n = (typeof len === "number") ? Math.min(len, buf.length) : buf.length;
  if (n < 12) return { valid: false, reason: "short-header" };

  const id     = (buf[0] << 8) | buf[1];
  const flags  = (buf[2] << 8) | buf[3];
  const qr     = (flags >> 15) & 0x1;
  const opcode = (flags >> 11) & 0xf;
  const tc     = (flags >> 9) & 0x1;
  const rcode  = flags & 0xf;
  const qdcount = (buf[4] << 8) | buf[5];
  const ancount = (buf[6] << 8) | buf[7];
  const nscount = (buf[8] << 8) | buf[9];
  const arcount = (buf[10] << 8) | buf[11];

  /* Sanity: standard query/response has opcode 0..2 and at least one
   * question. Counts in the thousands mean we're looking at non-DNS
   * bytes that happened to hit port 53. */
  if (opcode > 5) return { valid: false, reason: "bad-opcode" };
  if (qdcount === 0 || qdcount > 64) return { valid: false, reason: "bad-qdcount" };
  if (ancount > 1024 || nscount > 1024 || arcount > 1024) {
    return { valid: false, reason: "bad-counts" };
  }

  /* Parse the first question's QNAME starting at offset 12. */
  const parsed = parseName(buf, 12, n);
  if (!parsed) return { valid: false, reason: "bad-qname" };
  const { name, next } = parsed;

  /* QTYPE + QCLASS follow the name. */
  let qtype = 0, qclass = 0;
  if (next + 4 <= n) {
    qtype  = (buf[next] << 8) | buf[next + 1];
    qclass = (buf[next + 2] << 8) | buf[next + 3];
  }

  return {
    valid: true,
    id, is_query: qr === 0, opcode, rcode, truncated: tc === 1,
    qdcount, ancount, nscount, arcount,
    qname: name, qtype, qclass,
  };
}

/* Parse a DNS name (label sequence) starting at `off`. Returns
 * { name, next } where next is the offset just past the name, or null
 * on malformed input. Handles compression pointers (0xc0) by stopping
 * — in queries there usually aren't any, and we only need the text.
 * Caps total length to guard against loops in malformed data. */
function parseName(buf, off, n) {
  const labels = [];
  let i = off;
  let total = 0;
  let safety = 0;

  while (i < n) {
    if (safety++ > 128) return null;     /* malformed / loop guard */
    const lenByte = buf[i];

    if (lenByte === 0) {                 /* root label — name ends */
      i += 1;
      return { name: labels.join("."), next: i };
    }

    if ((lenByte & 0xc0) === 0xc0) {     /* compression pointer */
      /* We don't follow it (queries rarely use it, and we only need
       * the label text we already have). Treat the 2 pointer bytes as
       * the terminator. */
      i += 2;
      return { name: labels.join("."), next: i };
    }

    if ((lenByte & 0xc0) !== 0) return null;   /* reserved bits set */

    const labelLen = lenByte;
    i += 1;
    if (i + labelLen > n) return null;          /* runs past buffer */
    total += labelLen + 1;
    if (total > 255) return null;               /* DNS name max 255 */

    let label = "";
    for (let k = 0; k < labelLen; k++) {
      label += String.fromCharCode(buf[i + k]);
    }
    labels.push(label);
    i += labelLen;
  }

  return null;   /* ran off the end without a terminator */
}

/* Shannon entropy (bits per character) of a string. DGA-generated
 * names tend toward high entropy (random-looking); human/CDN names
 * tend lower. Computed over the whole name with dots removed. */
export function shannonEntropy(s) {
  if (!s || s.length === 0) return 0;
  const cleaned = s.replace(/\./g, "");
  if (cleaned.length === 0) return 0;
  const freq = new Map();
  for (const ch of cleaned) freq.set(ch, (freq.get(ch) || 0) + 1);
  let H = 0;
  const N = cleaned.length;
  for (const c of freq.values()) {
    const p = c / N;
    H -= p * Math.log2(p);
  }
  return H;
}

/* Ratio of digit characters in the name (DGA names are often digit-
 * heavy). 0..1. */
export function digitRatio(s) {
  if (!s || s.length === 0) return 0;
  let digits = 0, alnum = 0;
  for (const ch of s) {
    if (ch >= "0" && ch <= "9") { digits++; alnum++; }
    else if ((ch >= "a" && ch <= "z") || (ch >= "A" && ch <= "Z")) alnum++;
  }
  return alnum === 0 ? 0 : digits / alnum;
}

/* Longest label length in a dotted name. Long single labels are a
 * DNS-tunneling signal (data encoded into the subdomain). */
export function maxLabelLen(s) {
  if (!s) return 0;
  let max = 0;
  for (const label of s.split(".")) if (label.length > max) max = label.length;
  return max;
}

/* Extract a coarse "registrable domain" for grouping queries by parent.
 * This is a heuristic (no public-suffix list): take the last two labels
 * normally, last three for known two-level TLDs (co.uk, com.au, ...).
 * Good enough to group "a.tunnel.evil.com" and "b.tunnel.evil.com"
 * under "evil.com" for tunneling aggregation. */
const TWO_LEVEL_TLDS = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "com.au", "net.au",
  "org.au", "co.nz", "com.br", "com.cn", "co.in", "co.za",
]);
export function registrableDomain(name) {
  if (!name) return "";
  const parts = name.split(".").filter(Boolean);
  if (parts.length <= 2) return parts.join(".");
  const lastTwo = parts.slice(-2).join(".");
  if (TWO_LEVEL_TLDS.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }
  return lastTwo;
}

/* Bundle the per-query signals used by state + detection. */
export function querySignals(qname) {
  return {
    entropy: shannonEntropy(qname),
    digit_ratio: digitRatio(qname),
    max_label: maxLabelLen(qname),
    total_len: qname ? qname.length : 0,
    registrable: registrableDomain(qname),
  };
}
