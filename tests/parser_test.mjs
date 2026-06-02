/* Unit tests for the DNS parser. Run with: node tests/parser_test.mjs
 * (from the dnstop directory). No yeet runtime needed. */
import {
  parseDNS, qtypeName, shannonEntropy, digitRatio,
  maxLabelLen, registrableDomain, querySignals, RCODE_NXDOMAIN,
} from "../dns_parser.js";

function buildQuery(name, qtype = 1, opts = {}) {
  const labels = name.split(".").filter(Boolean);
  const b = [];
  b.push(0x12, 0x34);
  const flags = opts.response ? (0x8000 | (opts.rcode || 0)) : 0x0100;
  b.push((flags >> 8) & 0xff, flags & 0xff);
  b.push(0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
  for (const l of labels) { b.push(l.length); for (let i = 0; i < l.length; i++) b.push(l.charCodeAt(i)); }
  b.push(0x00);
  b.push((qtype >> 8) & 0xff, qtype & 0xff, 0x00, 0x01);
  return new Uint8Array(b);
}

let pass = 0, fail = 0;
const ok = (l, c) => { if (c) pass++; else { console.log("FAIL: " + l); fail++; } };

ok("basic A query", (() => { const r = parseDNS(buildQuery("www.example.com")); return r.valid && r.qname === "www.example.com" && r.qtype === 1; })());
ok("AAAA", parseDNS(buildQuery("a.b.com", 28)).qtype === 28);
ok("TXT name", parseDNS(buildQuery("x.evil.com", 16)).qtype === 16);
ok("response NXDOMAIN", (() => { const r = parseDNS(buildQuery("x.com", 1, { response: true, rcode: 3 })); return !r.is_query && r.rcode === RCODE_NXDOMAIN; })());
ok("short invalid", !parseDNS(new Uint8Array([0, 1, 2, 3])).valid);
ok("entropy random>english", shannonEntropy("x7f3k9q2zp1") > shannonEntropy("googlevideo"));
ok("digitRatio", Math.abs(digitRatio("abc123") - 0.5) < 0.001);
ok("maxLabelLen", maxLabelLen("a.bb.ccc") === 3);
ok("registrable", registrableDomain("a.b.evil.com") === "evil.com");
ok("registrable co.uk", registrableDomain("x.y.co.uk") === "y.co.uk");
ok("querySignals", querySignals("a.tunnel.evil.com").registrable === "evil.com");
ok("qtypeName", qtypeName(16) === "TXT" && qtypeName(1) === "A");

console.log(`${pass} pass, ${fail} fail`);
if (fail > 0) process.exit(1);
