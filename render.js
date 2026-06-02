/* Pure rendering toolkit for minertop: ANSI escapes, color ramps, a
 * braille canvas, address/port/byte formatters, and the mining pool
 * port database with coin-hint heuristics. No application state, no
 * I/O — safe to import anywhere. */

export const ESC = "\x1b[";
export const HOME = `${ESC}H`;
export const CLEAR = `${ESC}2J${ESC}H`;
export const HIDE = `${ESC}?25l`;
export const SHOW = `${ESC}?25h`;
export const RESET = `${ESC}0m`;
export const EOL = `${ESC}K`;
export const bold = `${ESC}1m`;
export const dim = `${ESC}2m`;
export const ital = `${ESC}3m`;
export const fg = (n) => `${ESC}38;5;${n}m`;
export const bg = (n) => `${ESC}48;5;${n}m`;

/* heat ramps for bandwidth strips */
export const HEAT_TX = [17, 18, 19, 20, 26, 32, 39, 45, 51, 50, 48, 46, 82, 118];
export const HEAT_RX = [52, 88, 124, 160, 196, 202, 208, 214, 220, 226, 190, 154, 118, 82];
export const SILENT_BG = 234;
export const EIGHTH = [" ", "▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"];

/* role colors */
export const C_AXIS   = 238;
export const C_DIM    = 240;
export const C_ALERT  = 196;    /* DGA / tunnel alert: red */
export const C_DGA    = 202;    /* DGA-flagged process: bright orange */
export const C_TUNNEL = 170;    /* tunneling-flagged domain: magenta */
export const C_HIGHE  = 178;    /* high-entropy query: amber */
export const C_NORMAL = 244;    /* ordinary query */
export const C_OK     = 84;     /* clean / safe */
export const C_QUERY  = 51;     /* query rate cyan */
export const C_TX     = 51;
export const C_RX     = 215;

/* ---- DNS-specific render helpers ----------------------------------
 * Color + glyph for a query based on its detection signals. */

export function entropyColor(entropy, highEntropy) {
  if (highEntropy) return C_HIGHE;
  if (entropy >= 3.0) return C_NORMAL;
  return C_DIM;
}

export function queryMark(rec) {
  if (rec.high_entropy) return "⚠";   /* warning: high-entropy name */
  if (rec.qtype === 16) return "T";          /* TXT */
  if (rec.proto === 1)  return "⤷";   /* TCP DNS */
  return "·";
}

/* ---- byte / rate formatters ---------------------------------------- */
const KB = 1024, MB = 1024 * 1024, GB = 1024 * 1024 * 1024, TB = 1024 * GB;
export function formatBytes(n) {
  if (!isFinite(n) || n < 0) return "—";
  if (n >= TB) return (n / TB).toFixed(n >= 10 * TB ? 0 : 1) + "TB";
  if (n >= GB) return (n / GB).toFixed(n >= 10 * GB ? 0 : 1) + "GB";
  if (n >= MB) return (n / MB).toFixed(n >= 10 * MB ? 0 : 1) + "MB";
  if (n >= KB) return (n / KB).toFixed(n >= 10 * KB ? 0 : 1) + "KB";
  return Math.round(n) + "B";
}
export function formatBps(bps) { return formatBytes(bps) + "/s"; }
export function compactNum(n) {
  if (!isFinite(n)) return "—";
  if (n >= 1e9) return (n / 1e9).toFixed(n >= 1e10 ? 0 : 1) + "G";
  if (n >= 1e6) return (n / 1e6).toFixed(n >= 1e7 ? 0 : 1) + "M";
  if (n >= 1e4) return (n / 1e3).toFixed(0) + "k";
  if (n >= 1e3) return (n / 1e3).toFixed(1) + "k";
  return String(Math.round(n));
}

/* ---- address formatters (mirror flowtop/bytetop's, with the
 * ::-collapse bugfix already incorporated) ---------------------------- */
export function fmtIPv4(bytes) {
  return `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`;
}
export function fmtIPv6(bytes) {
  const g = new Array(8);
  for (let i = 0; i < 8; i++) g[i] = (bytes[i * 2] << 8) | bytes[i * 2 + 1];
  if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 &&
      g[4] === 0 && g[5] === 0xffff) {
    return `::ffff:${bytes[12]}.${bytes[13]}.${bytes[14]}.${bytes[15]}`;
  }
  let bs = -1, bl = 0, cs = -1, cl = 0;
  for (let i = 0; i < 8; i++) {
    if (g[i] === 0) {
      if (cs === -1) { cs = i; cl = 1; } else cl++;
      if (cl > bl) { bs = cs; bl = cl; }
    } else { cs = -1; cl = 0; }
  }
  if (bl < 2) { bs = -1; bl = 0; }
  const parts = [];
  for (let i = 0; i < 8; ) {
    if (i === bs) { parts.push(""); i += bl; continue; }
    parts.push(g[i].toString(16));
    i++;
  }
  let s = parts.join(":");
  if (bs === 0) s = ":" + s;
  if (bs + bl === 8 && bs >= 0) s = s + ":";
  return s;
}
export function fmtAddr(family, bytes) {
  return family === 10 ? fmtIPv6(bytes) : fmtIPv4(bytes);
}
export function fmtEndpoint(family, bytes, port) {
  const addr = fmtAddr(family, bytes);
  return family === 10 ? `[${addr}]:${port}` : `${addr}:${port}`;
}

/* ---- time formatters ---------------------------------------------- */
export function mmss(ms) {
  const t = Math.floor(ms / 1000);
  const h = Math.floor(t / 3600);
  const m = Math.floor((t % 3600) / 60);
  const s = t % 60;
  const p = (n) => String(n).padStart(2, "0");
  return h > 0 ? `${p(h)}:${p(m)}:${p(s)}` : `${p(m)}:${p(s)}`;
}
export function fmtDuration(ms) {
  if (!isFinite(ms) || ms < 0) return "—";
  if (ms < 1000) return Math.round(ms) + "ms";
  const s = Math.round(ms / 1000);
  if (s < 60) return s + "s";
  const m = Math.floor(s / 60);
  if (m < 60) return m + "m " + (s % 60) + "s";
  const h = Math.floor(m / 60);
  return h + "h " + (m % 60) + "m";
}

/* ---- visible-length-aware string ops ------------------------------ */
export function vlen(s) {
  return String(s).replace(/\x1b\[[0-9;?]*[A-Za-z]/g, "").length;
}
export function clipAnsi(s, n) {
  let out = "", vis = 0, i = 0;
  while (i < s.length) {
    if (s[i] === "\x1b") {
      const m = /^\x1b\[[0-9;?]*[A-Za-z]/.exec(s.slice(i));
      if (m) { out += m[0]; i += m[0].length; continue; }
    }
    if (vis >= n) break;
    out += s[i]; vis++; i++;
  }
  return out + RESET;
}
export function fixw(s, w) {
  const v = vlen(s);
  if (v < w) s = s + " ".repeat(w - v);
  return clipAnsi(s, w);
}
export function padVis(s, n) {
  const pad = n - vlen(s);
  return pad > 0 ? s + " ".repeat(pad) : s;
}

/* ---- heat cells + sparklines + bars ------------------------------- */
export function heatCell(v, ramp) {
  if (v < 0) return bg(SILENT_BG) + " " + RESET;
  const r = ramp || HEAT_TX;
  return bg(r[Math.min(r.length - 1, Math.floor(v * r.length))]) + " " + RESET;
}
export function sparkline(hist, w, color = C_TX) {
  if (w <= 0 || hist.length === 0) return " ".repeat(Math.max(0, w));
  const vis = Math.min(w, hist.length);
  const start = hist.length - vis;
  let max = 0;
  for (let i = start; i < hist.length; i++) if (hist[i] > max) max = hist[i];
  let out = "";
  for (let i = 0; i < w - vis; i++) out += " ";
  if (max === 0) {
    for (let i = 0; i < vis; i++) out += fg(C_AXIS) + EIGHTH[0] + RESET;
  } else {
    for (let i = 0; i < vis; i++) {
      const v = hist[start + i] / max;
      const idx = Math.max(1, Math.min(8, Math.round(v * 8)));
      out += fg(color) + EIGHTH[idx] + RESET;
    }
  }
  return out;
}
export function hbar(val, max, w, color) {
  if (w <= 0) return "";
  if (max <= 0 || val <= 0) return fg(C_AXIS) + "▱".repeat(w) + RESET;
  const filled = Math.min(w, Math.floor((val / max) * w));
  const frac = ((val / max) * w) - filled;
  let out = fg(color) + "▰".repeat(filled);
  if (filled < w) {
    const sub = Math.round(frac * 8);
    if (sub > 0) out += EIGHTH[Math.min(8, sub)];
    else out += "▱";
    out += "▱".repeat(Math.max(0, w - filled - 1));
  }
  return out + RESET;
}
