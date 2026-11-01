#!/usr/bin/env node
// Differential ABI fuzz (r/ethdev feedback). Deterministic: SEED fixes every type, value and mutation.
// Phase 1 (valid): random type list + values -> encode with blocktools abi-encode; ethers v6 must encode the
//   same bytes; blocktools abi-decode, ethers, viem and `cast abi-decode` must all decode it back to the values.
// Phase 2 (mutated): change bytes of valid encodings; all four decoders must accept or reject together and,
//   when all accept, agree on the values. A disagreement where blocktools rejects on purpose (strict rules,
//   docs/ABI-STRICT.md) and another decoder accepts is counted against allow.json; anything else fails.
// Env: BT_BIN (dir with abi-encode, abi-decode), CAST (cast binary), SEED, VALID, MUTATIONS (per valid case),
//   MAX_SECONDS (stop early, reported). Prints one JSON summary line last; exit 1 on any unexpected result.
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { AbiCoder, Result } from "ethers";
import { decodeAbiParameters, parseAbiParameters } from "viem";

const env = (k, d) => process.env[k] ?? d;
const BIN = env("BT_BIN", "target/release"), CAST = env("CAST", "cast");
const SEED = Number(env("SEED", "20261101")), VALID = Number(env("VALID", "400"));
const MUT = Number(env("MUTATIONS", "5")), MAXS = Number(env("MAX_SECONDS", "1200"));
const allow = JSON.parse(readFileSync(new URL("./allow.json", import.meta.url))).entries;
const t0 = Date.now();

let s = SEED >>> 0; // mulberry32
const rnd = () => { s = (s + 0x6d2b79f5) >>> 0; let t = s; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
const ri = (a, b) => a + Math.floor(rnd() * (b - a + 1));
const pick = (xs) => xs[ri(0, xs.length - 1)];
const big = (bits) => { let v = 0n; for (let i = 0; i < bits; i += 16) v = (v << 16n) | BigInt(ri(0, 65535)); return v & ((1n << BigInt(bits)) - 1n); };
const hexb = (n) => "0x" + Array.from({ length: n }, () => ri(0, 255).toString(16).padStart(2, "0")).join("");

const WIDTHS = Array.from({ length: 32 }, (_, i) => 8 * (i + 1));
function rtype(d = 0) {
  const k = rnd();
  if (d < 3 && k < 0.12) return "(" + Array.from({ length: ri(1, 3) }, () => rtype(d + 1)).join(",") + ")";
  if (d < 3 && k < 0.22) return rtype(d + 1) + "[]";
  if (d < 3 && k < 0.28) return rtype(d + 1) + `[${ri(1, 3)}]`;
  return pick([() => `uint${pick(WIDTHS)}`, () => `int${pick(WIDTHS)}`, () => "address", () => "bool",
    () => `bytes${ri(1, 32)}`, () => "bytes", () => "string"])();
}
function split(t) { const out = []; let d = 0, cur = ""; for (const c of t) { if (c === "," && d === 0) { out.push(cur); cur = ""; continue; } if (c === "(") d++; if (c === ")") d--; cur += c; } if (cur) out.push(cur); return out; }
const STR = ["", "a", "hello", "é", "日本語", "🦀", "0", ",]}", "\"q\"", "a\\b"];
// value as blocktools takes it (ints decimal strings, bytes 0x-hex, arrays/tuples JSON arrays)
function rval(t) {
  if (t.endsWith("]")) { const i = t.lastIndexOf("["), inner = t.slice(0, i), n = t.slice(i + 1, -1); const len = n ? Number(n) : ri(0, 3); return Array.from({ length: len }, () => rval(inner)); }
  if (t.startsWith("(")) return split(t.slice(1, -1)).map(rval);
  if (t.startsWith("uint")) { const m = Number(t.slice(4)); return pick([0n, 1n, (1n << BigInt(m)) - 1n, big(m)]).toString(); }
  if (t.startsWith("int")) { const m = BigInt(t.slice(3)); return pick([0n, -1n, (1n << (m - 1n)) - 1n, -(1n << (m - 1n)), big(Number(m)) - (1n << (m - 1n))]).toString(); }
  if (t === "address") return pick(["0x0000000000000000000000000000000000000000", hexb(20)]);
  if (t === "bool") return rnd() < 0.5;
  if (t === "bytes") return hexb(pick([0, 1, 31, 32, 33, ri(0, 80)]));
  if (t === "string") return rnd() < 0.5 ? pick(STR) : Array.from({ length: ri(0, 40) }, () => String.fromCodePoint(pick([ri(32, 126), ri(0xa0, 0x7ff), ri(0x800, 0xd7ff), ri(0x10000, 0x1ffff)]))).join("");
  return hexb(Number(t.slice(5))); // bytesN
}
// canonical comparison form: ints decimal strings, hex lowercase, arrays of arrays
function norm(v) {
  if (v instanceof Result) v = v.toArray(true);
  if (Array.isArray(v)) return v.map(norm);
  if (typeof v === "bigint" || typeof v === "number") return v.toString();
  if (typeof v === "string") return /^0x[0-9a-fA-F]*$/.test(v) ? v.toLowerCase() : v;
  return v;
}
// strings that look like hex must stay strings: compare with type info
function normT(t, v) {
  if (t.endsWith("]")) { const inner = t.slice(0, t.lastIndexOf("[")); return Array.from(v instanceof Result ? v.toArray(false) : v, (x) => normT(inner, x)); }
  if (t.startsWith("(")) { const ts = split(t.slice(1, -1)); const a = Array.from(v instanceof Result ? v.toArray(false) : v); return ts.map((tt, i) => normT(tt, a[i])); }
  if (t === "string") return v;
  if (t === "bool") return v;
  if (typeof v === "string") return /^-?\d+$/.test(v) ? v : v.toLowerCase();
  return norm(v);
}
const run = (cmd, args, input) => spawnSync(cmd, args, { input, encoding: "utf8", maxBuffer: 64 << 20 });
const numsAsText = (txt) => JSON.parse(txt, (k, v, c) => (typeof v === "number" ? c.source : v));

const coder = AbiCoder.defaultAbiCoder();
const dec = {
  blocktools(types, list, data) {
    const r = run(`${BIN}/abi-decode`, ["--types", `(${list})`, data]);
    const o = JSON.parse(r.stdout.trim().split("\n").pop() || "{}");
    if (r.status !== 0 || o.status !== "ok") return { ok: false, err: o.error ?? `exit_${r.status}` };
    return { ok: true, v: o.args.map((a, i) => normT(types[i], a.value)) };
  },
  ethers(types, list, data) {
    try { const r = coder.decode(types, data); return { ok: true, v: types.map((t, i) => normT(t, r[i])) }; }
    catch (e) { return { ok: false, err: String(e.code ?? e.shortMessage ?? e.message).slice(0, 80) }; }
  },
  viem(types, list, data) {
    try { const r = decodeAbiParameters(parseAbiParameters(list), data); return { ok: true, v: types.map((t, i) => normT(t, r[i])) }; }
    catch (e) { return { ok: false, err: String(e.name ?? e.message).slice(0, 80) }; }
  },
  cast(types, list, data) {
    const r = run(CAST, ["abi-decode", "--json", `f()(${list})`, data]);
    if (r.status !== 0) return { ok: false, err: (r.stderr || "").trim().split("\n")[0].slice(0, 80) };
    const o = numsAsText(r.stdout);
    return { ok: true, v: types.map((t, i) => normT(t, o.data[i])) };
  },
};
const NAMES = Object.keys(dec);
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const allowed = (name, ourErr) => allow.find((a) => a.decoder === name &&
  (a.our_error.endsWith("*") ? new RegExp("^" + a.our_error.slice(0, -1) + "\\d+$").test(ourErr) : ourErr === a.our_error));

const sum = { seed: SEED, valid_target: VALID, mutations_per_valid: MUT, valid: 0, valid_ok: 0, encode_mismatch_ethers: 0,
  valid_disagree: 0, mutated: 0, mutated_all_reject: 0, mutated_all_accept_same: 0, mutated_allowlisted: 0, unexpected: 0,
  by_allow: {}, by_unexpected: {}, examples: [], stopped_early: false };
const bad = (kind, detail) => { sum.unexpected++; sum.by_unexpected[kind] = (sum.by_unexpected[kind] ?? 0) + 1; if (sum.examples.length < 25) sum.examples.push({ kind, ...detail }); };

function mutate(hex) {
  const b = Buffer.from(hex.slice(2), "hex");
  const k = ri(0, 6);
  if (k === 0 && b.length) { b[ri(0, b.length - 1)] ^= 1 << ri(0, 7); return ["bitflip", b]; }
  if (k === 1 && b.length >= 32) { const w = ri(0, b.length / 32 - 1) * 32; b[w + 31] = (b[w + 31] + pick([1, 32, 0xe0, 0xff])) & 0xff; return ["word_low_byte", b]; }
  if (k === 2 && b.length >= 32) { const w = ri(0, b.length / 32 - 1) * 32; b[w + ri(0, 23)] = ri(1, 255); return ["word_high_byte", b]; }
  if (k === 3 && b.length) return ["truncate", b.subarray(0, ri(0, b.length - 1))];
  if (k === 4) return ["append", Buffer.concat([b, Buffer.alloc(pick([1, 31, 32, 64]), ri(0, 1) ? 0 : 0xab)])];
  if (k === 5 && b.length >= 32) { const w = ri(0, b.length / 32 - 1) * 32; b.fill(0xff, w, w + 32); return ["word_all_ff", b]; }
  if (b.length) { b[ri(0, b.length - 1)] = ri(0, 255); return ["byte_set", b]; }
  return ["append", Buffer.from([0])];
}

for (let i = 0; i < VALID; i++) {
  if ((Date.now() - t0) / 1000 > MAXS) { sum.stopped_early = true; break; }
  const types = Array.from({ length: ri(1, 4) }, () => rtype());
  const list = types.join(","), vals = types.map(rval);
  const r = run(`${BIN}/abi-encode`, ["--raw"], JSON.stringify({ sig: `(${list})`, args: vals }));
  if (r.status !== 0) { bad("our_encode_failed", { types: list, err: r.stderr.trim() }); continue; }
  const data = r.stdout.trim();
  sum.valid++;
  const want = types.map((t, k) => normT(t, vals[k]));
  let ethersEnc;
  try { ethersEnc = coder.encode(types, vals); } catch (e) { ethersEnc = "ERR " + (e.code ?? e.message); }
  if (ethersEnc !== data) { sum.encode_mismatch_ethers++; bad("encode_mismatch_ethers", { types: list, ours: data.slice(0, 200), ethers: String(ethersEnc).slice(0, 200) }); }
  let okAll = true;
  for (const n of NAMES) {
    const d = dec[n](types, list, data);
    if (!d.ok || !same(d.v, want)) { okAll = false; bad(`valid_${n}_${d.ok ? "value_differs" : "rejected"}`, { types: list, data: data.slice(0, 400), err: d.err, got: d.ok ? JSON.stringify(d.v).slice(0, 300) : undefined, want: JSON.stringify(want).slice(0, 300) }); }
  }
  okAll ? sum.valid_ok++ : sum.valid_disagree++;
  for (let m = 0; m < MUT; m++) {
    const [kind, b] = mutate(data);
    const md = "0x" + b.toString("hex");
    if (md === data) continue;
    sum.mutated++;
    const res = Object.fromEntries(NAMES.map((n) => [n, dec[n](types, list, md)]));
    const acc = NAMES.filter((n) => res[n].ok);
    if (acc.length === 0) { sum.mutated_all_reject++; continue; }
    if (acc.length === NAMES.length) {
      if (NAMES.every((n) => same(res[n].v, res.blocktools.v))) { sum.mutated_all_accept_same++; continue; }
      bad("mutated_all_accept_values_differ", { kind, types: list, data: md.slice(0, 400), values: Object.fromEntries(NAMES.map((n) => [n, JSON.stringify(res[n].v).slice(0, 200)])) });
      continue;
    }
    const detail = { kind, types: list, data: md.slice(0, 400), result: Object.fromEntries(NAMES.map((n) => [n, res[n].ok ? "accept" : `reject:${res[n].err}`])) };
    if (res.blocktools.ok) { bad("mutated_blocktools_accepts_other_rejects", detail); continue; }
    // blocktools rejected; every accepting decoder must be allow-listed for this error, and accepting decoders must agree
    const e = res.blocktools.err;
    const unl = acc.filter((n) => !allowed(n, e));
    if (unl.length) { bad(`mutated_not_allowlisted:${e}`, detail); continue; }
    sum.mutated_allowlisted++;
    for (const n of acc) { const key = `${n}:${e.startsWith("dirty_") ? e.replace(/\d+$/, "N") : e}`; sum.by_allow[key] = (sum.by_allow[key] ?? 0) + 1; }
  }
}
sum.seconds = Math.round((Date.now() - t0) / 1000);
sum.versions = {
  node: process.version,
  ethers: JSON.parse(readFileSync(new URL("./node_modules/ethers/package.json", import.meta.url))).version,
  viem: JSON.parse(readFileSync(new URL("./node_modules/viem/package.json", import.meta.url))).version,
  cast: (run(CAST, ["--version"]).stdout || "").split("\n")[0].trim(),
};
for (const ex of sum.examples) console.log("EXAMPLE " + JSON.stringify(ex));
console.log("ABI-FUZZ " + JSON.stringify(sum));
process.exit(sum.unexpected || sum.stopped_early || sum.valid < VALID ? 1 : 0);
