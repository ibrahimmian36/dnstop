# dnstop

Live, per-process view of the DNS queries leaving your box, on eBPF. It shows which process asked for what, and flags two behaviors that usually mean something's wrong: domain-generation algorithms (DGA) and DNS tunneling.

```
$ yeet run https://github.com/ibrahimmian36/dnstop -- --audit
```

Built on [yeet](https://yeet.cx).

<p align="center"><img src="assets/dnstop.gif" alt="dnstop demo" width="820"></p>

## What it detects

Most malicious traffic resolves a name before it connects, so DNS is a good place to watch. dnstop looks for two things.

**DGA (domain-generation algorithms).** Malware that can't ship a fixed C2 address generates piles of random-looking domains and tries them until one resolves. So you get a process firing off lots of high-entropy names across lots of different registrable domains. dnstop computes the Shannon entropy of every query name and flags a process once it's made enough high-entropy lookups across enough distinct domains. This works whether the malware is one long-running process or the kind that forks a fresh short-lived process per lookup (it aggregates the same signal across PIDs sharing a process name).

**DNS tunneling.** Exfiltration that stuffs data into subdomain labels and ships it out as queries, e.g. `<base32-chunk>.tunnel.attacker.com`. Here you get the opposite shape: tons of unique subdomains under a single registrable domain, with very long labels, often TXT records. dnstop tracks how many distinct subdomains it sees per domain and the longest label.

Because DGA spreads queries across many domains and tunneling piles them under one, the two checks key off opposite signals. That's also why they don't fire on each other, or on ordinary high-volume traffic.

## Why it doesn't false-positive on normal traffic

Two fair objections: CDNs use high-entropy hostnames like `d3a1b2c4.cloudfront.net`, and big sites have hundreds of subdomains. Neither trips dnstop:

- A CDN's hash-like names all sit under one registrable domain. DGA detection needs high entropy *across many* registrable domains, so a process hammering cloudfront stays clean.
- A site with 50 subdomains (`mail.`, `drive.`, `docs.`, ...) uses short labels. Tunnel detection needs *long* labels (40+ chars), so normal subdomain sprawl stays clean.

Both cases are in the test suite.

## Verify it works

`tests/simulate_dns_threats.sh` fires both attack patterns at your system resolver using made-up names (all NXDOMAIN, nothing connects):

```sh
# shell 1
yeet run main.js -- --audit --duration 30

# shell 2
./tests/simulate_dns_threats.sh
```

After the scan window closes you'll see a DGA alert for the script's process and a tunnel alert for `tunnel-demo.example`.

The DNS parser also has standalone unit tests:

```sh
node tests/parser_test.mjs
```

## Audit mode

One-shot scan with a verdict. Pipe-friendly stdout.

```sh
yeet run main.js -- --audit                       # 60s
yeet run main.js -- --audit --duration 120        # longer
yeet run main.js -- --audit --json | tee out.json # machine-readable
```

Clean output:

```
════════════════════════════════════════════════════════════════
  dnstop audit · DNS query behavior scan
════════════════════════════════════════════════════════════════

  Duration:     1m 0s

── Queries observed ────────────────────────────────────────────
  DNS queries seen:       2843
  Distinct processes:     14
  Distinct domains:       186

── DGA detection ───────────────────────────────────────────────
  ✓ no DGA-like processes

── Tunneling detection ─────────────────────────────────────────
  ✓ no tunnel-like domains

════════════════════════════════════════════════════════════════
VERDICT: NO DGA OR TUNNELING DETECTED
════════════════════════════════════════════════════════════════
```

## Live mode

```sh
yeet run main.js
```

```
 ▌ DNSTOP · DNS query observatory ─────────────────────────────────────────────────────────────────────────────
● LIVE 00:42   38 q/s   14 procs   186 domains                                              ⚠ 1 DGA · 1 tunnel

  ⚠ DNS ALERTS · DGA / tunneling detections ───────────────────────────────────────────────────────────────────
  DGA   suspicious-proc   pid 6821   42 high-entropy lookups across 39 domains
  TUNNEL evil-exfil.com               118 unique subdomains · max label 57 · 118 TXT

  PROCESSES · query sources (⚠ DGA-flagged) · rate · unique domains · avg entropy ──────────────────────────────
   ⚠ suspicious-proc  pid 6821    18 q/s     39 dom   H 3.81   ▂▃▅▇▆▅▃▂
   · chrome           pid 1204    12 q/s     22 dom   H 2.64   ▃▄▃▅▄▃▄▅
   · node             pid 3310    6 q/s      8 dom    H 2.41   ▁▂▁▂▃▂▁▁

  DOMAINS · registrable domains by query volume (⚠ tunnel-flagged) ─────────────────────────────────────────────
   ⚠ evil-exfil.com                     118 q   118 sub   lbl 57
   · github.com                          84 q   12 sub    lbl 14
   · google.com                          52 q   22 sub    lbl 9

  QUERY FEED · newest first · ⚠ high-entropy name · T TXT ──────────────────────────────────────────────────────
   00:42  ⚠ A      x7f3k9q2zp1w8v.com                              suspicious-proc
   00:42  T  TXT    aGVsbG8gd29ybGQ.evil-exfil.com                  curl
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Anonymize before sharing a screenshot:

```sh
yeet run main.js -- --anonymize
```

## Limitations

- Encrypted DNS is invisible. DoH (DNS-over-HTTPS) and DoT (DNS-over-TLS) wrap queries in TLS to a resolver on port 443/853. dnstop hooks plaintext UDP/TCP port 53, so it sees the traditional resolver path but not DoH/DoT. On most servers and default Linux desktops, port 53 is still the path; browsers doing their own DoH are the main blind spot.
- Query-side only in v1. Detection runs on outbound queries. NXDOMAIN-rate tracking from responses (a strong DGA confirmation signal) needs the response path, which is planned for v2.
- Detection is threshold-based. A slow DGA that stays under the volume threshold, or a tunnel using short labels with many queries, can evade. The thresholds favor low false positives over catching every variant; they're constants at the top of `state.js` if you want to tune them.
- Registrable-domain grouping uses a short built-in two-level-TLD list, not the full Public Suffix List. Grouping for obscure multi-level TLDs may be coarse.

## Under the hood

Two BPF programs feed one ring buffer:

| program          | hook                       | does what                                |
|------------------|----------------------------|-------------------------------------------|
| `on_udp_sendmsg` | `fentry/udp_sendmsg`       | capture outbound UDP DNS (dport 53)       |
| `on_tcp_sendmsg` | `fentry/tcp_sendmsg`       | capture DNS-over-TCP (dport 53)           |

The kernel side filters for destination port 53, grabs up to 256 bytes of the query payload via `bpf_probe_read_user`, and ships it. All DNS wire-format parsing, entropy scoring, and detection happens in JavaScript. CO-RE throughout; no fixed offsets.

```
main.js         entry; live vs audit dispatch; BPF bind + subscribe
dns_parser.js   DNS wire format + entropy / tunneling signals
state.js        per-process + per-domain aggregation; DGA + tunnel detection
audit.js        one-shot scan + report (human + JSON)
render.js       ANSI, formatters, sparklines
dashboard.js    panels and layout for live mode
```

## Requirements

- Linux ≥ 5.5 (for `fentry`). Debian 13, Ubuntu 22.04+, Fedora 36+, recent Arch.
- Kernel BTF (`CONFIG_DEBUG_INFO_BTF=y`), default on the above.
- `CAP_BPF` + `CAP_PERFMON`. yeet handles this.
- `clang` and `bpftool` for the BPF object. `yeet run` invokes them on first launch.

## Build from a clone

```sh
git clone https://github.com/ibrahimmian36/dnstop
cd dnstop
make
yeet run main.js
```

`make clean` removes `bin/`. `make distclean` also removes `include/vmlinux.h`.
