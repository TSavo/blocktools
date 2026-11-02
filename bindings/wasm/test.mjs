// Node smoke test of the wasm package against public vectors. Run by scripts/wasm-check.sh.
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
const bt = createRequire(import.meta.url)('./pkg/node/blocktools_wasm.js');
const X = 'xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V';
const rows = JSON.parse(bt.addressesFromXpub(X, 'btc', ['p2wpkh'], new Uint32Array([0]), new Uint32Array([0, 1])));
assert.equal(rows[0].address, 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu');
assert.equal(rows[1].address, 'bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g');
assert.equal(bt.validateAddress('btc', rows[0].address), 'SegwitV0');
assert.throws(() => bt.validateAddress('btc', rows[0].address.slice(0, -1) + 'x'));
assert.equal(bt.validateAddress('xmr', '44cWztNFdAqNnycvZbUoj44vsbAEmKnx9aNgkjHdjtMsBrSeKiY8J4s2raH7EMawA2Fwo9utaRTV7Aw8EcTMNMxhH4YtKdH'), 'Xmr');
assert.throws(() => bt.validateAddress('xmr', '44cWztNFdAqNnycvZbUoj44vsbAEmKnx9aNgkjHdjtMsBrSeKiY8J4s2raH7EMawA2Fwo9utaRTV7Aw8EcTMNMxhH4YtKdx'));
assert.ok(JSON.parse(bt.listChains()).includes('eth'));
assert.ok(JSON.parse(bt.listChains()).includes('zec'));
assert.ok(JSON.parse(bt.chainTable()).find(c => c.name === 'btc').coin_type === 0);
assert.equal(JSON.parse(bt.supportedChains()).find(c => c.name === 'zec').scope, 'transparent');
const plan = JSON.parse(bt.explainPlan(['--chain', 'btc', '--preset', 'common']));
assert.ok(plan.length > 0 && plan.every(p => p.path.startsWith('m/')));
const b170 = readFileSync(new URL('../../crates/tx/tests/vectors/block170.hex', import.meta.url), 'utf8');
const lines = JSON.parse(bt.decodeTx(b170, 'btc'));
{ // Novacoin explorer JSON -> raw hex, hash-checked
  const t = 'c053a3fddd508df8cadd90bf8c987c35802c2779a8a19b4efc8c83124d11df20';
  const j = readFileSync(new URL('../../crates/tx/tests/data/nvc_c053a3fd.json', import.meta.url), 'utf8');
  const hex = bt.serializeNvcTxFromJson(j, t);
  assert.equal(hex.length, 180 * 2);
  assert.ok(JSON.stringify(JSON.parse(bt.decodeTx(hex, 'nvc'))).includes(t));
  const bad = JSON.parse(j); bad.time += 1;
  assert.throws(() => bt.serializeNvcTxFromJson(JSON.stringify(bad), t));
}
assert.ok(JSON.stringify(lines).includes('f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16'));
const v = JSON.parse(bt.verifyTx(b170, 'btc', ['1Q2TWHE3GMdB6BZKafqwxXtWAWgFt5Jvm3'], ['12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S'], undefined, '', true));
assert.equal(typeof v.ok, 'boolean');
{ // offline policy file: listed recipient + change pass the file's rules; unknown fee is still a base refusal
  const pol = JSON.stringify({version:1,chains:{btc:{allow_to:['1Q2TWHE3GMdB6BZKafqwxXtWAWgFt5Jvm3'],change:['12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S']}}});
  const r = JSON.parse(bt.checkTxPolicy(b170, 'btc', pol));
  assert.ok(!r.failures.includes('policy:allow_to') && r.failures.includes('fee_unknown') && r.policy_sha256.length === 64, JSON.stringify(r.failures));
  const r2 = JSON.parse(bt.checkTxPolicy(b170, 'btc', JSON.stringify({version:1,chains:{btc:{allow_to:[]}}})));
  assert.ok(r2.failures.includes('policy:allow_to'));
  assert.deepEqual(JSON.parse(bt.checkTxPolicy(b170, 'btc', JSON.stringify({version:1,chains:{}}))).failures, ['policy:no_rule_for_chain']);
  assert.throws(() => bt.checkTxPolicy(b170, 'btc', '{"version":2,"chains":{}}'), /policy_bad_version/);
  console.log('ok checkTxPolicy');
}
{
  const cs = JSON.parse(readFileSync(new URL('../../crates/blocktools/tests/data/sol-build-corpus.json', import.meta.url), 'utf8'));
  for (const c of cs.slice(0, 12)) {
    const plan = { from: c.from, to: c.to, blockhash: c.blockhash, priority: c.priority ?? undefined };
    if (c.kind === 'send') plan.lamports = c.lamports; else if (c.kind === 'sweep') plan.sweep_balance = c.balance;
    else plan.token = { mint: c.mint, amount: c.amount, decimals: c.decimals, token_program: c.token_program, create_ata: c.create_ata };
    assert.equal(bt.solBuildTransfer(JSON.stringify(plan)), c.tx);
  }
  assert.throws(() => bt.solBuildTransfer(JSON.stringify({ from: cs[0].from, to: cs[0].from, blockhash: cs[0].blockhash, lamports: '1' })), /from_equals_to/);
  console.log('ok solBuildTransfer');
}
{
  // Mainnet block 60,000,000 TRX transfer (crates/blocktools/src/tron.rs) rebuilt from its fields.
  const TRX = '0a0286ec220805d9f8c360a410c440d0d78ad1e4315a65080112610a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412300a15418380d3e5288ecab17c89827a4dd17652d13e7264121541ee0a85ee960f6da8c50292d3dd07ea291c133ed1180170859087d1e431';
  const plan = { from: 'TMxXrJ5u3Qsh7scpn4zRUzrxYtBoPCW5GM', to: 'TXfrRsqwPbMi4Leb4EGB7dv5NMMWmkdRwk', ref_block_bytes: '86ec', ref_block_hash: '05d9f8c360a410c4',
    expiration_ms: '1710640770000', timestamp_ms: '1710640711685', amount_sun: '1' };
  assert.equal(bt.tronBuildTransfer(JSON.stringify(plan)), TRX);
  assert.throws(() => bt.tronBuildTransfer(JSON.stringify({ ...plan, amount_sun: '0' })), /zero_amount/);
  console.log('ok tronBuildTransfer');
}
const v2 = JSON.parse(bt.verifyTx(b170, 'btc', ['bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu'], [], undefined, '', true));
assert.equal(v2.ok, false);
// Stable API (EXPORTS.md)
assert.match(bt.version(), /^\d+\.\d+\.\d+/);
const sup = JSON.parse(bt.supportedChains()), unv = JSON.parse(bt.unverifiedChains());
assert.ok(sup.every(c => c.verified === true) && unv.every(c => c.verified === false));
assert.ok(sup.some(c => c.name === 'qtum') && sup.some(c => c.name === 'xpm') && unv.some(c => c.name === 'wdc'));
assert.ok(!sup.some(c => unv.some(u => u.name === c.name)));
const d = JSON.parse(bt.deriveFromXpub('btc', X, 'm/0', 1));
assert.ok(d.some(r => r.kind === 'p2wpkh' && r.address === 'bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g' && r.path === 'm/0/1'));
assert.throws(() => bt.deriveFromXpub('wdc', X, '0', 0));
assert.equal(bt.addressValidate('btc', '1Q2TWHE3GMdB6BZKafqwxXtWAWgFt5Jvm3'), 'P2pkh');
assert.throws(() => bt.addressValidate('wdc', 'WZMJS5eeCEgiqxNK1QRbE1HR4wFQwmCjJV'));
const ck = q => JSON.parse(bt.checkTx(JSON.stringify(q)));
const q = {chain: 'btc', raw_tx_hex: b170.trim(), expected_outputs: [{address: '1Q2TWHE3GMdB6BZKafqwxXtWAWgFt5Jvm3', amount: '1000000000'}], max_fee: 0, owner_addr: '12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S', input_values: [5000000000]};
assert.deepEqual(ck(q).reasons, []); assert.equal(ck(q).ok, true);
assert.equal(ck({...q, max_fee: undefined}).ok, false);
assert.equal(ck({...q, chain: 'wdc'}).ok, false);
assert.equal(JSON.parse(bt.checkTx('{')).ok, false);
// coins: detect (all candidates), convert, params, sweep
{ const i = JSON.parse(bt.detectAddressInfo("1BoatSLRHtKNngkdXEeobR76b53LETtpyT"));
  if (!i.ambiguous || !i.kinds_agree || !i.candidates.some(c => c.chain === "btc")) throw new Error("detectAddressInfo btc");
  const j = JSON.parse(bt.detectAddressInfo("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"));
  if (j.ambiguous || j.candidates.length !== 1 || j.candidates[0].chain !== "btc") throw new Error("detectAddressInfo bech32");
  if (JSON.parse(bt.detectAddressInfo("nope")).candidates.length !== 0) throw new Error("detectAddressInfo empty");
  // XLS-5d test vector (xrpl.org address-codec): X-address -> kind "xaddress"; classic r-address stays "Xrp"
  const x = JSON.parse(bt.detectAddressInfo("X7AcgcsBL6XDcUb289X4mJ8djcdyKaB5hJDWMArnXr61cqZ"));
  if (x.candidates.length !== 1 || x.candidates[0].chain !== "xrp" || x.candidates[0].kind !== "xaddress") throw new Error("detectAddressInfo xaddress " + JSON.stringify(x));
  if (bt.validateAddress("xrp", "X7AcgcsBL6XDcUb289X4mJ8djcdyKaB5hJDWMArnXr61cqZ") !== "Xrp") throw new Error("xaddr validate");
  const r = JSON.parse(bt.detectAddressInfo("r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59"));
  if (r.candidates[0].kind !== "Xrp") throw new Error("r-address kind"); }
const det = a => JSON.parse(bt.detectAddress(a)).map(x => x.chain).sort();
assert.deepEqual(det('DFpN6QqFfUm3gKNaxN6tNcab1FArL9cZLE'), ['dgb', 'doge', 'pivx']);
assert.deepEqual(det('t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs'), ['zec']);
assert.equal(bt.convertAddress('1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH', 'zec'), 't1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs');
assert.equal(bt.addressValidate('zec', 't1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs'), 'P2pkh');
const P = JSON.parse(bt.chainParams()); const pr = n => P.find(r => r.name === n);
assert.equal(pr('ppc').decimals, 6); assert.equal(pr('btg').forkid, 79); assert.equal(pr('dash').sweep_build, true);
assert.equal(pr('atom').hrp, 'cosmos'); assert.equal(pr('wdc').slip44, null); assert.equal(pr('bch').sweep_build, true); assert.equal(pr('eth').sweep_build, false);
{ const T = JSON.parse(bt.chainTable()); const tr = n => T.find(c => c.name === n);
  assert.equal(tr('bch').buildable, pr('bch').sweep_build); assert.equal(tr('eth').buildable, pr('eth').sweep_build);
  assert.equal(tr('wdc').coin_type, null); assert.equal(tr('wdc').buildable, false); }
const dashA = bt.convertAddress('1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH', 'dash');
const sw = JSON.parse(bt.buildUnsignedSweep('dash', '{"txid":"75213284b51c45476cd7ac67386452786f8016f547ed064af04905af96e25bd5","vout":0,"amount":100000,"address":"XmN7PQYWKn5MJFna5fRYgP6mxT2F7xpekE","prev_tx":"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff020101ffffffff01a0860100000000001976a914751e76e8199196d454941c45d1b3a323f1433bd688ac00000000"}', dashA, 10));
assert.equal(sw.fee, '1930'); assert.equal(sw.tx_format, 'legacy');
assert.ok(JSON.stringify(JSON.parse(bt.decodeTx(sw.unsigned_tx, 'dash'))).includes(dashA));
assert.throws(() => bt.buildUnsignedSweep('pot', '', dashA, 10));
// legacy input amount must match its prev_tx (legacy sighash does not commit to it), and prev_tx is required
assert.throws(() => bt.buildUnsignedSweep('dash', '{"txid":"75213284b51c45476cd7ac67386452786f8016f547ed064af04905af96e25bd5","vout":0,"amount":10000,"address":"XmN7PQYWKn5MJFna5fRYgP6mxT2F7xpekE","prev_tx":"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff020101ffffffff01a0860100000000001976a914751e76e8199196d454941c45d1b3a323f1433bd688ac00000000"}', dashA, 10), /prev_tx|amount/);
assert.throws(() => bt.buildUnsignedSweep('dash', JSON.stringify({...JSON.parse('{"txid":"75213284b51c45476cd7ac67386452786f8016f547ed064af04905af96e25bd5","vout":0,"amount":100000,"address":"XmN7PQYWKn5MJFna5fRYgP6mxT2F7xpekE","prev_tx":"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff020101ffffffff01a0860100000000001976a914751e76e8199196d454941c45d1b3a323f1433bd688ac00000000"}'), prev_tx: undefined}), dashA, 10), /prev_tx/);
{ // PoS-nTime (Peercoin): raw tx + prevouts, nTime right after the version
  const ppcA = 'PKGSi8HTQzLx89rkZrRrVkPFjrcSC55NP9';
  const u = '{"txid":"53afd998f418f2917ed7c4bd8a7ec04c6f47361aa9ac1ea2d8d9c1ce9471e103","vout":0,"amount":100000,"address":"PKGSi8HTQzLx89rkZrRrVkPFjrcSC55NP9","prev_tx":"0100000000f15365010707070707070707070707070707070707070707070707070707070707070707000000000151ffffffff01a0860100000000001976a914751e76e8199196d454941c45d1b3a323f1433bd688ac00000000"}';
  const p = JSON.parse(bt.buildUnsignedSweepAt('ppc', u, ppcA, 10, 1792800000));
  assert.equal(p.tx_format, 'pos-ntime'); assert.equal(p.psbt, undefined); assert.equal(p.pos_prevouts.length, 1);
  assert.equal(p.unsigned_tx.slice(8, 16), '00f5db6a'); // 1792800000 LE
  assert.throws(() => bt.buildUnsignedSweep('ppc', u, ppcA, 10)); // wasm has no clock: time required
  { // amounts above 2^53 round-trip exactly as strings (RDD whale sweep)
    const rddA = 'RjJ4cn5Bg58D2khGiNRmQW1yWtA6Py9kWa', big = '9007199254740993';
    const r = JSON.parse(bt.buildUnsignedSweepAt('rdd', '{"txid":"19db44a77447d34cf87e14e7e962b137cd76a60dc1a2bfab2a205c0281f2bcfc","vout":0,"amount":"9007199254740993","address":"RjJ4cn5Bg58D2khGiNRmQW1yWtA6Py9kWa","prev_tx":"02000000010707070707070707070707070707070707070707070707070707070707070707000000000151ffffffff0101000000000020001976a914751e76e8199196d454941c45d1b3a323f1433bd688ac0000000000f15365"}', rddA, 10, 1792800000));
    assert.equal(BigInt(r.amount_str) + BigInt(r.fee_str), BigInt(big));
    assert.equal(r.pos_prevouts[0].amount_str, big);
    assert.equal(r.amount, r.amount_str); // sweep amount/fee were already strings; twins are uniform
  }
}
{ // Zcash transparent v5: ZIP-317 minimum fee, raw tx + zec_prevouts, header 0x80000005 + v5 group id
  const zA = 't1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs';
  const z = JSON.parse(bt.buildUnsignedSweep('zec', JSON.stringify({txid: '0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9', vout: 0, amount: 1000000, address: zA}), zA, 1));
  assert.equal(z.tx_format, 'zcash-v5'); assert.equal(z.fee, '10000'); assert.equal(z.unsigned_tx.slice(0, 16), '050000800a27a726');
  assert.ok(bt.decodeTx(JSON.stringify(z), 'zec').includes(zA));
}
console.log('wasm node test ok (verify block170 expected-to:', v.ok, v.failures.join(',') + ')');
// Groestlcoin (groestlcoinjs-lib vectors): Groestl checksum, unique F.../grs1, and a 3... that BTC rejects
assert.equal(bt.validateAddress('grs', 'Fob4maNwBGVRPmMcRLS6qtTJfKeySAMsWq'), 'P2pkh');
assert.equal(bt.validateAddress('grs', 'grs1qw508d6qejxtdg4y5r3zarvary0c5xw7k3k4sj5'), 'SegwitV0');
assert.deepEqual(JSON.parse(bt.detectAddress('3JvL6Ymt8MVWiCNHC7oWU6nLeHNJFpSXbA')).map(c => c.chain), ['grs']);
assert.throws(() => bt.validateAddress('btc', '3JvL6Ymt8MVWiCNHC7oWU6nLeHNJFpSXbA'));
{ const g = JSON.parse(bt.chainParams()).find(c => c.name === 'grs');
  assert.equal(g.checksum, 'groestl512d'); assert.equal(g.tx_format, 'legacy-sha256'); assert.equal(g.verified, true); }
console.log('wasm grs ok');
{ // Substrate / BLAKE2b (vectors: Python hashlib, xxhash, py-scale-codec, Alice dev account)
  const A = 'd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d';
  assert.equal(bt.blake2b('', 32, ''), '0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8');
  assert.equal(bt.blake2b('616263', 32, 'ZcashSigHash'), '63d3a98d9443ac4fbad669a9fd31cb2ec8db244e8d27878b19129da671f11ef4');
  assert.throws(() => bt.blake2b('zz', 32, ''));
  assert.equal(bt.twox128('System'), '26aa394eea5630e07c48ae0c9558cef7');
  assert.equal(bt.ss58Encode(A, 0), '15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5');
  assert.equal(bt.ss58Encode(A, 1284), 'VdvKmYJfD4VXA9fzz1SbmCo2eYHSzUFbaDCZSuaNKJAe8YNg6');
  assert.deepEqual(JSON.parse(bt.ss58Decode('5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY')), {prefix: 42, account: A});
  const K = '26aa394eea5630e07c48ae0c9558cef7b99d880ec681799c0cf30e8886371da9de1e86a9a8c739864cf3cc5ec2bea59f' + A;
  assert.equal(bt.polkadotAccountStorageKey('15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5'), K);
  assert.equal(bt.polkadotAccountStorageKey('0x' + A), K);
  const ai = JSON.parse(bt.decodeAccountInfo('07000000010000000100000000000000d20a1feb8ca954ab0000000000000000050000000000000000000000000000000010a5d4e8000000000000000000000000000000000000000000000000000080'));
  assert.equal(ai.nonce, 7); assert.equal(ai.data.free, '12345678901234567890');
  console.log('wasm substrate ok');
}
{ // Solana (vectors: solders find_program_address / is_on_curve / Transaction bytes)
  const O = '9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM', USDC = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', TK = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
  assert.deepEqual(JSON.parse(bt.solAssociatedTokenAddress(O, USDC, '')), {address: 'FGETo8T8wMcN2wCjav8VK6eh3dLk63evNDPxzLSJra8B', bump: 254});
  assert.deepEqual(JSON.parse(bt.solFindProgramAddress(JSON.stringify([Buffer.from('vault').toString('hex'), bt.base58Decode(O)]), TK)), {address: 'Duvp5BivpbCj7kPqjzGFUMRuwmv1BBNMp4FvSsLkjZAZ', bump: 254});
  assert.equal(bt.solIsOnCurve(O), true); assert.equal(bt.solIsOnCurve('FGETo8T8wMcN2wCjav8VK6eh3dLk63evNDPxzLSJra8B'), false);
  assert.equal(bt.solAnchorDiscriminator('initialize'), 'afaf6d1f0d989bed');
  assert.equal(bt.base58Encode(bt.base58Decode(O)), O);
  const L = '010e63fc82a30c1b2e0587e81cce44e17d6b9e756e1494fc5b34efce519239d2b78128fa5e9aa95018fdc59649bea55c03c07a8a001f9060a356f1cdd50234f00f010001038a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c7e8c088760bfde1dddcf32c17f209b8242ee52aaf131facd88d0ea2c6d0b06f20000000000000000000000000000000000000000000000000000000000000000c49ae77603782054f17a9decea43b444eba0edb12c6f1d31c6e0e4a84bf052eb01020200010c0200000087d6120000000000';
  for (const raw of [L, Buffer.from(L, 'hex').toString('base64')]) {
    const d = JSON.parse(bt.solDecodeTx(raw));
    assert.equal(d.txid, 'HgsP3r893euWYPRfiZv5b8P6SrWhx3z2whQWMfpkhFwgEgnxQMXmufFmXa4c9c9WaFRkWnd6AdNmzHjJJqvLDLA');
    assert.equal(d.instructions[0].kind, 'system_transfer'); assert.equal(d.signatures[0].status, 'valid');
  }
  assert.equal(JSON.parse(bt.solVerifyTx(L, JSON.stringify({to: O, lamports: '1234567'}))).ok, true);
  assert.deepEqual(JSON.parse(bt.solVerifyTx(L, JSON.stringify({to: USDC}))).failures.sort(), ['recipient_not_paid', 'unexpected_recipient:' + O].sort());
  console.log('wasm solana ok');
}
{ // CashAddr (spec vectors) + address <-> script
  assert.equal(bt.cashAddrToLegacy('bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a'), '1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu');
  assert.equal(bt.legacyToCashAddr('3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC', ''), 'bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq');
  assert.deepEqual(JSON.parse(bt.cashAddrDecode('bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t')), {prefix: 'bchtest', type: 'p2sh', hash: 'f5bf48b397dae70be82b3cca4793f8eb2b6cdac9'});
  assert.equal(bt.cashAddrEncode('bitcoincash', 'p2pkh', 'f5bf48b397dae70be82b3cca4793f8eb2b6cdac9'), 'bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2');
  assert.throws(() => bt.cashAddrDecode('bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg3'));
  const s = bt.addressToScript('bch', 'qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a');
  assert.equal(s, '76a91476a04053bda0a88bda5177b86a15c3b29f55987388ac');
  assert.deepEqual(JSON.parse(bt.scriptToAddress('bch', s)), {kind: 'p2pkh', address: '1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu'});
  assert.equal(bt.addressToScript('btc', 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'), '0014751e76e8199196d454941c45d1b3a323f1433bd6');
  assert.equal(bt.scriptToAddress('btc', '6a0568656c6c6f'), 'null');
  console.log('wasm cashaddr ok');
}
{ // PSBT+memo (embit byte-for-byte) and Tron (mainnet block 60,000,000)
  const U = JSON.stringify({txid: '0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9', vout: 0, amount: 100000, address: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'});
  const p = JSON.parse(bt.buildPsbtWithMemo('btc', U, 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu', '', '', 5, Buffer.from('hi').toString('hex'), true)); // embit vector is RBF
  assert.equal(p.psbt, 'cHNidP8BAF8CAAAAAcmXpeVuEEEC+iCcaoUt2QZgogstnDUkI+3OJYV/zTcEAAAAAAD9////AjmEAQAAAAAAFgAUwM681sPTyox13F7GLr5VMw75EOIAAAAAAAAAAARqAmhpAAAAAAABAR+ghgEAAAAAABYAFHUedugZkZbUVJQcRdGzoyPxQzvWAAAA');
  assert.equal(p.fee, '615'); assert.equal(p.outputs[1].address, null);
  { // default (7 args, or rbf false) = non-RBF nSequence 0xffffffff: THORChain inbound txs must not be RBF
    const args = ['btc', U, 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu', '', '', 5, Buffer.from('hi').toString('hex')];
    const d = JSON.parse(bt.buildPsbtWithMemo(...args)), f = JSON.parse(bt.buildPsbtWithMemo(...args, false));
    assert.equal(d.psbt, f.psbt); assert.equal(d.rbf, false); assert.equal(p.rbf, true);
    assert.equal(d.psbt, p.psbt.replace('AAD9////', 'AAD/////')); assert.equal(d.fee, p.fee);
  }
  { // THORChain order [vault, change, OP_RETURN]; empty memo = no OP_RETURN
    const q = JSON.parse(bt.buildPsbtWithMemo('btc', U, 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu', '50000', 'bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g', 5, Buffer.from('=:ETH.ETH:0x0000000000000000000000000000000000000001').toString('hex')));
    assert.deepEqual(q.outputs.map(o => o.value), ['50000', '48980', '0']); assert.ok(q.outputs[2].script.startsWith('6a'));
    const e = JSON.parse(bt.buildPsbtWithMemo('btc', U, 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu', '50000', 'bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g', 5, ''));
    assert.equal(e.outputs.length, 2); assert.equal(e.fee, '705'); assert.equal(e.vsize, 141);
    // SwapChan regression: 76-byte memo, rate 22, 89494 sats over 5 UTXOs, send 44747 -> sub-dust change folds into the fee.
    const F = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4';
    const R = [21259, 30300, 7443, 18169, 12323].map((v, i) => JSON.stringify({ txid: (0xc0de00 + i).toString(16).padStart(64, 'b'), vout: i % 2, amount: v, address: F })).join('\n');
    const g = JSON.parse(bt.buildPsbtWithMemo('btc', R, 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu', '44747', F, 22, Buffer.from('y'.repeat(76)).toString('hex')));
    assert.deepEqual(g.outputs.map(o => o.value), ['44747', '0']); assert.equal(g.fee, String(30300 + 21259 - 44747));
    // verifyThorSend: the honest PSBT q passes; named reasons for wrong vault / memo case / amount / foreign taker / garbage.
    const V = 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu', C = 'bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g', M = '=:ETH.ETH:0x0000000000000000000000000000000000000001';
    const ok = JSON.parse(bt.verifyThorSend('btc', q.psbt, V, M, '50000', C, F, ''));
    assert.equal(ok.ok, true); assert.equal(ok.memo, M); assert.equal(ok.fee, '1020'); assert.equal(ok.rbf, false);
    assert.deepEqual(JSON.parse(bt.verifyThorSend('btc', q.psbt, C, M, '50000', C, F, '')).failures, ['vault']);
    assert.deepEqual(JSON.parse(bt.verifyThorSend('btc', q.psbt, V, M.toLowerCase(), '50000', C, F, '')).failures, ['memo']);
    assert.deepEqual(JSON.parse(bt.verifyThorSend('btc', q.psbt, V, M, '50001', C, F, '')).failures, ['amount']);
    assert.deepEqual(JSON.parse(bt.verifyThorSend('btc', q.psbt, V, M, '50000', C, JSON.stringify([C]), '')).failures, ['input_foreign']);
    assert.deepEqual(JSON.parse(bt.verifyThorSend('btc', q.psbt, V, M, '50000', C, F, '1019')).failures, ['fee']);
    assert.deepEqual(JSON.parse(bt.verifyThorSend('btc', 'zz', V, M, '50000', C, '', '')).failures, ['tx']);
  }
  const T = '0a0286ec220805d9f8c360a410c440d0d78ad1e4315a65080112610a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412300a15418380d3e5288ecab17c89827a4dd17652d13e7264121541ee0a85ee960f6da8c50292d3dd07ea291c133ed1180170859087d1e431';
  assert.equal(bt.tronTxId(T), '07755381b660a83a2767b8de974e88257797d2865c6dde14eccfe69c23717d00');
  const d = JSON.parse(bt.tronDecodeTx(T)); assert.equal(d.contracts[0].type, 'TransferContract'); assert.equal(d.contracts[0].amount_sun, '1');
  assert.equal(bt.validateAddress('tron', d.contracts[0].to), 'Tron');
  console.log('wasm psbt-memo + tron ok');
}

// XRP address validation / detection (public: rrrrrrrrrrrrrrrrrrrrrhoLvTp = ACCOUNT_ZERO, rHb9... = genesis)
{
  assert.equal(bt.validateAddress('xrp', 'rrrrrrrrrrrrrrrrrrrrrhoLvTp'), 'Xrp');
  assert.equal(bt.validateAddress('xrp', 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh'), 'Xrp');
  assert.throws(() => bt.validateAddress('xrp', 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTi'));
  assert.ok(det('rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh').includes('xrp'), 'detectAddress finds xrp');
  assert.ok(!det('rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTi').includes('xrp'));
}
// Recovery verifier (SwapChan verifyRecovery / verifySweepTx twins)
{
  const owner = '0x1111111111111111111111111111111111111111', now = 1761400000;
  const v = JSON.parse(bt.verifyRecovery(JSON.stringify({ to: '0x2222222222222222222222222222222222222222', data: '0x3ccfd60b', value: '0' }), owner, now));
  assert.deepEqual(v, { verified: true, call: 'withdraw()' });
  assert.equal(JSON.parse(bt.verifyRecovery(JSON.stringify({ to: owner, data: '0x3ccfd60b', value: '1' }), owner, now)).reason, 'non-zero value');
  assert.throws(() => bt.verifyRecovery('{}', owner, 0), /bad_now/);
  assert.throws(() => bt.verifyRecovery('nope', owner, now), /bad_json/);
  const s = JSON.parse(bt.verifySweepTx(JSON.stringify({ from: owner, to: owner, value: '5', chainId: 1 }), owner, 1, ''));
  assert.equal(s.verified, true);
  assert.equal(JSON.parse(bt.verifySweepTx(JSON.stringify({ from: owner, to: owner, value: '5', chainId: 10 }), owner, 1, '')).verified, false);
  // unsigned 1559 legacy-free raw: 0x02 || rlp([1,0,1,1,100000,to,0,0x3ccfd60b,[]])
  const raw = '0x02e40180010183' + '0186a0' + '94' + '22'.repeat(20) + '80' + '84' + '3ccfd60b' + 'c0';
  const r = JSON.parse(bt.verifyRecoveryRaw(raw, owner, 1, now));
  assert.equal(r.verified, true, JSON.stringify(r)); assert.equal(r.tx.signed, false); assert.equal(r.tx.chainId, 1);
  assert.equal(JSON.parse(bt.verifyRecoveryRaw(raw, owner, 5, now)).verified, false);
  assert.equal(JSON.parse(bt.verifySweepRaw(raw, owner, 1, '')).reason, 'from is not the owner');
  const t = JSON.parse(bt.recoveryTables());
  assert.ok(t.standard_recovery.length > 30 && t.exit_deadline_max_s === 3600, Object.keys(t).join());
}
console.log('verifier + xrp ok');
// addressToScript: zec t1/t3 and all-uppercase bech32 (BIP-173), mixed case rejected
{
  for (const s of ['76a914' + '11'.repeat(20) + '88ac', 'a914' + '22'.repeat(20) + '87']) {
    const a = JSON.parse(bt.scriptToAddress('zec', s)).address;
    assert.ok(/^t[13]/.test(a), a); assert.equal(bt.addressToScript('zec', a), s);
  }
  const p = '0014' + 'ab'.repeat(20);
  for (const c of ['btc', 'btg', 'ltc', 'ftc', 'dgb', 'vtc', 'via', 'qtum', 'mona', 'grs', 'rdd', 'ppc', 'nmc', 'mec']) {
    const r = JSON.parse(bt.scriptToAddress(c, p)); if (!r) { console.log('no bech32 for', c); continue }
    const a = r.address;
    assert.equal(bt.addressToScript(c, a.toUpperCase()), p, c);
    const mixed = a.slice(0, -1) + a.slice(-1).toUpperCase();
    if (mixed !== a) { assert.throws(() => bt.addressToScript(c, mixed), /bad_address/, c) }
  }
}
console.log('addressToScript case + zec ok');
{ // Solana v1 (SIMD-0385) tx signed by @solana/kit 8.5 (throwaway key)
  const d = JSON.parse(bt.solDecodeTx('810100011f000000cc490e928cd2e3873bb343fc95da33179ca60f4dbf46c2c36e91299d55d4e6b90103ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a0000000000000000000000000000000000000000000000000000000000000000611e000000000000400d0300000001000000010002020c000001020000008813000000000000b28e1fbd5898b73280f71909a504f13474152e16999f669450b734cf4c3c613844c746c2c6657204f62e4570bd3cc87715f5cf51dadf997033c96a91fb386901'));
  assert.equal(d.version, 1); assert.equal(d.config.priority_fee_lamports, '7777'); assert.equal(d.signatures[0].status, 'valid');
  assert.equal(typeof d.instructions[0].data_hex, 'string'); assert.ok(Array.isArray(d.instructions[0].account_indexes));
  const v = JSON.parse(bt.solVerifyTx('810100011f000000cc490e928cd2e3873bb343fc95da33179ca60f4dbf46c2c36e91299d55d4e6b90103ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a0000000000000000000000000000000000000000000000000000000000000000611e000000000000400d0300000001000000010002020c000001020000008813000000000000b28e1fbd5898b73280f71909a504f13474152e16999f669450b734cf4c3c613844c746c2c6657204f62e4570bd3cc87715f5cf51dadf997033c96a91fb386901', '{}')); assert.equal(v.fully_signed, true);
  // decodeTx/verifyTx with chain 'sol' used to fall through to the bitcoin parser (bad_transaction).
  const sraw = '810100011f000000cc490e928cd2e3873bb343fc95da33179ca60f4dbf46c2c36e91299d55d4e6b90103ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a0000000000000000000000000000000000000000000000000000000000000000611e000000000000400d0300000001000000010002020c000001020000008813000000000000b28e1fbd5898b73280f71909a504f13474152e16999f669450b734cf4c3c613844c746c2c6657204f62e4570bd3cc87715f5cf51dadf997033c96a91fb386901';
  assert.deepEqual(JSON.parse(bt.decodeTx(sraw, 'sol')), JSON.parse(bt.solDecodeTx(sraw)));
  assert.throws(() => bt.verifyTx(sraw, 'sol', [], [], undefined, '', false, undefined), /solana_use_solVerifyTx/);
  console.log('sol v1 ok');
}
{ // Contract Read/Write: buildEvmTransfer data/create, evmApproveCall, verifyTx callJson, evmAbiEncode from a JSON ABI
  const to = '0x' + 'aa'.repeat(20);
  const abi = JSON.stringify([{type:'function',name:'store',inputs:[{name:'v',type:'uint256'}]},{type:'function',name:'store',inputs:[{name:'v',type:'uint256'},{name:'w',type:'bool'}]}]);
  const enc = JSON.parse(bt.evmAbiEncode(JSON.stringify({abi, name: 'store', args: ['42']})));
  assert.equal(enc.name, 'store'); assert.ok(enc.data.startsWith('0x6057361d'), JSON.stringify(enc));
  assert.throws(() => bt.evmAbiEncode(JSON.stringify({abi, name: 'nope', args: []})), /no_such_function/);
  const enc2 = JSON.parse(bt.evmAbiEncode(JSON.stringify({abi, name: 'store', args: ['42', true]})));
  assert.equal(enc2.signature, 'store(uint256,bool)');
  const c = JSON.parse(bt.buildEvmTransfer(JSON.stringify({chainId: 1, nonce: 3, gas: 60000, gasPrice: '7', to, data: enc2.data})));
  assert.equal(c.value, '0'); assert.equal(c.to, to); assert.equal(c.data, enc2.data);
  assert.throws(() => bt.buildEvmTransfer(JSON.stringify({chainId: 1, nonce: 3, gasPrice: '7', to, data: enc.data})), /missing_gas/);
  const ok = JSON.parse(bt.evmApproveCall(JSON.stringify({to, data: enc.data, abi})));
  assert.equal(ok.status, 'ok', JSON.stringify(ok));
  assert.equal(JSON.parse(bt.evmApproveCall(JSON.stringify({to, data: enc.data, sigs: ['other(uint256)']}))).status, 'unknown_selector');
  const k = JSON.parse(bt.buildEvmTransfer(JSON.stringify({chainId: 1, nonce: 0, gas: 100000, gasPrice: '7', create: '0x' + '5b'.repeat(120)})));
  assert.equal(k.to, null); assert.equal(k.initcode_keccak256.length, 66);
  assert.equal(JSON.parse(bt.evmApproveCall(JSON.stringify({to: null, data: k.data, createHash: k.initcode_keccak256}))).status, 'ok');
  const plain = JSON.parse(bt.verifyTx(c.unsigned, 'eth', [to], [], 1, '', false));
  assert.equal(plain.ok, false); assert.equal(plain.call, undefined);
  const v = JSON.parse(bt.verifyTx(c.unsigned, 'eth', [to], [], 1, '', false, undefined, JSON.stringify({abi})));
  assert.equal(v.ok, true, JSON.stringify(v)); assert.equal(v.call.status, 'ok');
  const bad = JSON.parse(bt.verifyTx(c.unsigned, 'eth', [to], [], 1, '', false, undefined, JSON.stringify({sigs: ['other(uint256)']})));
  assert.equal(bad.ok, false);
  const kv = JSON.parse(bt.verifyTx(k.unsigned, 'eth', [], [], 1, '', false, undefined, JSON.stringify({createHash: k.initcode_keccak256})));
  assert.equal(kv.ok, true, JSON.stringify(kv));
  console.log('contract read/write ok');
}
// lift 7: buildEvmTransfer / selectUtxos
{
  const to = '0x' + '01'.repeat(20);
  const b = JSON.parse(bt.buildEvmTransfer(JSON.stringify({ chainId: 61, nonce: 0, gas: 21000, gasPrice: '1000000000', to, balance: '1000000000000000000' })));
  assert.equal(b.kind, 'legacy'); assert.equal(b.value, (10n ** 18n - 21000n * 10n ** 9n).toString()); assert.equal(b.fee, '21000000000000');
  assert.ok(b.unsigned.startsWith('0x') && b.sighash.length === 66);
  const t = JSON.parse(bt.buildEvmTransfer(JSON.stringify({ chainId: 56, nonce: 1, gas: 65000, gasPrice: '3', to, value: '5', token: '0x' + 'ee'.repeat(20), maxPriorityFeePerGas: '1' })));
  assert.equal(t.kind, 'eip1559'); assert.equal(t.value, '0'); assert.equal(t.recipient, to); assert.equal(t.amount, '5'); assert.ok(t.data.startsWith('0xa9059cbb'));
  assert.throws(() => bt.buildEvmTransfer(JSON.stringify({ chainId: 1, nonce: 0, gas: 21000, gasPrice: '1', to, balance: '100' })), /insufficient_balance/);
  const own = '0014' + 'ab'.repeat(20);
  const s = JSON.parse(bt.selectUtxos(JSON.stringify([{ txid: '00', vout: 0, value: 100, script: own }, { txid: '01', vout: 0, value: 90000, script: own }, { txid: '02', vout: 1, value: 50000, script: '00' }]), own, 10));
  assert.deepEqual([s.count, s.total, s.dropped_uneconomic, s.dropped_foreign, s.min_value], [1, '90000', 1, 1, '29600']);
}
console.log('lift7 ok');
// Security regression: 9.99 ETH fee refused on every wasm verify path (shared policy::check default cap).
{
  const tx = readFileSync(new URL('../../crates/blocktools/tests/data/evm-fee-9.99eth.txt', import.meta.url), 'utf8').trim();
  const to = '0x3535353535353535353535353535353535353535';
  const v = JSON.parse(bt.verifyTx(tx, 'eth', [to], [], 1, '', true));
  assert.equal(v.ok, false); assert.ok(v.failures.includes('fee_above_cap'), JSON.stringify(v)); assert.match(v.check_these, /CHECK THESE/);
  const p = JSON.parse(bt.checkTxPolicy(tx, 'eth', JSON.stringify({version:1,chains:{eth:{chain_id:1,allow_to:[to]}}})));
  assert.equal(p.ok, false); assert.ok(p.failures.includes('policy:max_fee'), JSON.stringify(p));
  const c = JSON.parse(bt.checkTx(JSON.stringify({chain:'eth',raw_tx_hex:tx,expected_outputs:[{address:to}],owner_addr:to,max_fee:'10000000000000000',chain_id:1})));
  assert.equal(c.ok, false);
  console.log('ok fee-cap 9.99 ETH refused (verifyTx, checkTxPolicy, checkTx)');
}
{ // describeTx + convertAddressFrom (previously uncalled; docs/EXPORTS-reference.md is generated from these calls)
  const d = bt.describeTx(b170, 'btc');
  assert.ok(d.includes('OUT #0: 1Q2TWHE3GMdB6BZKafqwxXtWAWgFt5Jvm3 10.00000000') && d.includes('fee    : UNKNOWN'), d);
  assert.throws(() => bt.describeTx('zz', 'btc'));
  const z = bt.convertAddressFrom('btc', '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH', 'zec');
  assert.equal(z, 't1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs');
  assert.equal(bt.base58Decode(z).slice(4, 44), bt.base58Decode('1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH').slice(2, 42)); // same hash160
  assert.throws(() => bt.convertAddressFrom('btc', '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMx', 'zec'));
  console.log('ok describeTx, convertAddressFrom');
}
{ // documented input limits (docs/EXPORTS-reference.md quotes them from the .d.ts doc comments)
  const TK = 'TokenkegQfeZyiNwAMbNbGKPFXCWuBvf9Ss623VQ5DA';
  bt.blake2b('', 32, 'a'.repeat(16)); assert.throws(() => bt.blake2b('', 32, 'a'.repeat(17)), /bad_personal/);
  bt.blake2b('', 64, ''); assert.throws(() => bt.blake2b('', 65, ''), /bad_out_len/); assert.throws(() => bt.blake2b('', 0, ''), /bad_out_len/);
  assert.throws(() => bt.decodeAccountInfo('00'.repeat(79)), /bad_length/); assert.throws(() => bt.decodeAccountInfo('00'.repeat(81)), /bad_length/);
  bt.solFindProgramAddress(JSON.stringify(['5eed'.repeat(16)]), TK); assert.throws(() => bt.solFindProgramAddress(JSON.stringify(['aa'.repeat(33)]), TK), /bad_seeds/);
  bt.solFindProgramAddress(JSON.stringify(Array(15).fill('aa')), TK); assert.throws(() => bt.solFindProgramAddress(JSON.stringify(Array(16).fill('aa')), TK), /bad_seeds/);
  const U = JSON.stringify({txid: '0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9', vout: 0, amount: 100000, address: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'});
  const m = n => bt.buildPsbtWithMemo('btc', U, 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu', '', '', 5, 'ab'.repeat(n));
  m(1); m(80); assert.throws(() => m(81), /memo_length/); assert.equal(JSON.parse(m(0)).outputs.length, 1); // empty memo = no OP_RETURN
  console.log('ok documented input limits (blake2b, decodeAccountInfo, solFindProgramAddress, memo)');
}
// EVM contract data: selectors/topics (EIP-20), keccak("") (Yellow Paper), lookup only against supplied signatures.
{
  assert.equal(bt.evmKeccak256('0x'), '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
  const s = JSON.parse(bt.evmSigHash('function transfer(address to, uint256 amount)'));
  assert.equal(s.selector, '0xa9059cbb'); assert.equal(s.signature, 'transfer(address,uint256)'); assert.equal(s.kind, 'function');
  const e = JSON.parse(bt.evmSigHash('event Transfer(address indexed from, address indexed to, uint256 value)'));
  assert.equal(e.topic, '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef');
  const l = JSON.parse(bt.evmSigLookup('0x5bf6f916', 'error LengthMismatch()\nerror TransactionDeadlinePassed()'));
  assert.deepEqual(l.matches, ['error TransactionDeadlinePassed()']);
  assert.equal(JSON.parse(bt.evmSigLookup('0xa9059cbb', 'error LengthMismatch()')).status, 'no_match');
  assert.throws(() => bt.evmSigHash('f(uint7)'), /./);
  console.log('ok evm sig');
}

{ // finding 10: a non-string argument (e.g. numeric lamports' error object, or a number) must throw a
  // TypeError, not corrupt wasm memory ("memory access out of bounds"), and the module must stay usable.
  let e; try { bt.solBuildTransfer(JSON.stringify({ from: 'AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9', to: '11111111111111111111111111111112', blockhash: '11111111111111111111111111111111', lamports: 5 })) } catch (x) { e = x }
  assert.match(String(e), /bad_number/);
  for (const arg of [e, 5, {}, undefined]) {
    assert.throws(() => bt.solDecodeTx(arg), (x) => x instanceof TypeError && /expected_string/.test(x.message));
    assert.throws(() => bt.addressValidate(arg, 'btc'), (x) => x instanceof TypeError && /expected_string/.test(x.message));
  }
  assert.throws(() => bt.solDecodeTx('00'), (x) => /^[a-z_]+$/.test(x.message));  // still usable after: a normal error
  console.log('ok non-string args throw TypeError expected_string (finding 10)');
}

{ // finding 1: BCH CashAddr shows up in detectAddress / detectAddressInfo
  const i = JSON.parse(bt.detectAddressInfo('bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a'));
  assert.ok(JSON.stringify(i.candidates).includes('bch'), JSON.stringify(i));
  console.log('ok cashaddr detect bch (finding 1)');
}
{ // evmAbiDecode: a mainnet USDC transfer (recipes/fixtures/evm-mainnet/01a) and Error(string) revert data
  const input = '0xa9059cbb000000000000000000000000264bd8291fae1d75db2c5f573b07faa6715997b5000000000000000000000000000000000000000000000000000000012d08aab0';
  const d = JSON.parse(bt.evmAbiDecode(JSON.stringify({input, sig: 'transfer(address,uint256)'})));
  assert.equal(d.args[0].value, '0x264bd8291fAE1D75DB2c5F573b07faA6715997B5'); assert.equal(d.args[1].value, '5050510000');
  assert.equal(JSON.parse(bt.evmAbiDecode(JSON.stringify({input, sig: 'approve(address,uint256)'}))).status, 'no_match');
  const r = JSON.parse(bt.evmAbiDecode(JSON.stringify({input: '0x08c379a0' + '0000000000000000000000000000000000000000000000000000000000000020' + '0000000000000000000000000000000000000000000000000000000000000002' + '6869' + '0'.repeat(60)})));
  assert.equal(r.signature, 'Error(string)'); assert.equal(r.args[0].value, 'hi');
  assert.throws(() => bt.evmAbiDecode(JSON.stringify({input: input.slice(0, -2), sig: 'transfer(address,uint256)'})), /./);
  console.log('ok evm abi decode');
  // allow_trailing (opt-in): an ERC-2771-style 20-byte suffix is refused by default, returned as trailing_hex when allowed
  const sfx = '22'.repeat(20);
  assert.throws(() => bt.evmAbiDecode(JSON.stringify({input: input + sfx, sig: 'transfer(address,uint256)'})), /trailing_data/);
  const t = JSON.parse(bt.evmAbiDecode(JSON.stringify({input: input + sfx, sig: 'transfer(address,uint256)', allow_trailing: true})));
  assert.equal(t.args[1].value, '5050510000'); assert.equal(t.trailing_hex, '0x' + sfx);
  const w = (n) => n.toString(16).padStart(64, '0');
  const g = JSON.parse(bt.evmAbiDecode(JSON.stringify({input: '0x' + w(1) + w(2) + w(3), types: '(uint112,uint112)', allow_trailing: true})));
  assert.equal(g.args[1].value, '2'); assert.equal(g.trailing_hex, '0x' + w(3));
  assert.throws(() => bt.evmAbiDecode(JSON.stringify({input: '0x01' + w(0).slice(2) + w(1) + sfx, types: '(address,uint256)', allow_trailing: true})), /dirty_address/);
  assert.throws(() => bt.evmAbiDecode(JSON.stringify({input: input + sfx, sig: 'transfer(address,uint256)', allow_trailing: 'true'})), /allow_trailing_must_be_bool/);
  console.log('ok evm abi decode allow_trailing');
  // allow_gaps (opt-in, separate): LI.FI-shaped partial decode, tuple offset 0x60 after two unconsumed head words
  const tup = w(7) + w(0x40) + w(4) + '6e656172'.padEnd(64, '0');
  const gIn = '0x' + w(0x60) + w(1) + w(2) + tup;
  assert.throws(() => bt.evmAbiDecode(JSON.stringify({input: gIn, types: '((uint256,string))'})), /non_canonical_offset/);
  assert.throws(() => bt.evmAbiDecode(JSON.stringify({input: gIn, types: '((uint256,string))', allow_trailing: true})), /non_canonical_offset/);
  const gp = JSON.parse(bt.evmAbiDecode(JSON.stringify({input: gIn, types: '((uint256,string))', allow_gaps: true})));
  assert.equal(gp.args[0].value[1], 'near'); assert.equal(gp.gap_bytes, 64); assert.equal(gp.trailing_hex, undefined);
  assert.throws(() => bt.evmAbiDecode(JSON.stringify({input: gIn + w(5), types: '((uint256,string))', allow_gaps: true})), /trailing_data/);
  const gt = JSON.parse(bt.evmAbiDecode(JSON.stringify({input: gIn + w(5), types: '((uint256,string))', allow_gaps: true, allow_trailing: true})));
  assert.equal(gt.trailing_hex, '0x' + w(5)); assert.equal(gt.gap_bytes, 64);
  assert.throws(() => bt.evmAbiDecode(JSON.stringify({input: gIn, types: '((uint256,string))', allow_gaps: 1})), /allow_gaps_must_be_bool/);
  console.log('ok evm abi decode allow_gaps');
}

{ // evmAbiEncodePacked: Solidity ABI spec "Non-standard Packed Mode" examples
  const p = JSON.parse(bt.evmAbiEncodePacked(JSON.stringify({types: '(int16,bytes1,uint16,string)', args: ['-1', '0x42', '3', 'Hello, world!']})));
  assert.equal(p.data, '0xffff42000348656c6c6f2c20776f726c6421');
  assert.equal(JSON.parse(bt.evmAbiEncodePacked(JSON.stringify({types: '(uint16)', args: ['0x12']}))).data, '0x0012');
  assert.throws(() => bt.evmAbiEncodePacked(JSON.stringify({types: '(string[])', args: [['a']]})), /packed_array_element/);
}
{ // evmAbiEncode: Solidity ABI spec example baz(uint32,bool) 69,true, and a round trip through evmAbiDecode
  const e = JSON.parse(bt.evmAbiEncode(JSON.stringify({sig: 'baz(uint32,bool)', args: ['69', true]})));
  assert.equal(e.selector, '0xcdcd77c0');
  assert.equal(e.data, '0xcdcd77c0' + '45'.padStart(64, '0') + '1'.padStart(64, '0'));
  const d = JSON.parse(bt.evmAbiDecode(JSON.stringify({input: e.data, sig: 'baz(uint32,bool)'})));
  assert.equal(d.args[0].value, '69'); assert.equal(d.args[1].value, true);
  const raw = JSON.parse(bt.evmAbiEncode(JSON.stringify({sig: '(uint8)', args: ['7']})));
  assert.equal(raw.types, '(uint8)');
  assert.throws(() => bt.evmAbiEncode(JSON.stringify({sig: 'f(uint8)', args: ['256']})), /value_too_large/);
  console.log('ok evm abi encode');
}

{ // evmCreateAddress: EIP-1014 example 1, and a CREATE nonce-0 address
  const z = '0x' + '00'.repeat(20);
  const c2 = JSON.parse(bt.evmCreateAddress(JSON.stringify({deployer: z, salt: '0x' + '00'.repeat(32), init_code: '0x00'})));
  assert.equal(c2.address, '0x4D1A2e2bB4F88F0250f26Ffff098B0b30B26BF38'); assert.equal(c2.scheme, 'create2');
  const c = JSON.parse(bt.evmCreateAddress(JSON.stringify({deployer: '0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0', nonce: 0})));
  assert.equal(c.address.toLowerCase(), '0xcd234a471b72ba2f1ccf0a70fcaba648a5eecd8d');
  assert.throws(() => bt.evmCreateAddress(JSON.stringify({deployer: z})), /create_needs_nonce_or_salt/);
  console.log('ok evm create address');
}

{ // evmAbiInspect: ERC-165 id from EIP-165, and the transferFrom / gasprice_bit_ether collision
  const v = JSON.parse(bt.evmAbiInspect('function supportsInterface(bytes4) view returns (bool)\nfunction transferFrom(address,address,uint256)\nfunction gasprice_bit_ether(int128)'));
  assert.equal(v.functions, 3);
  assert.deepEqual(v.interfaces.find((i) => i.interface === 'ERC-165'), {interface: 'ERC-165', complete: true, interface_id: '0x01ffc9a7'});
  assert.equal(v.selector_collisions[0].selector, '0x23b872dd');
  assert.throws(() => bt.evmAbiInspect('['), /bad_abi_json/);
  console.log('ok evm abi inspect');
}

{ // evmBytecodeInspect: EIP-1167 reference proxy and an EIP-7702 delegation designator
  const p = JSON.parse(bt.evmBytecodeInspect('0x363d3d373d3d3d363d73' + 'be'.repeat(20) + '5af43d82803e903d91602b57fd5bf3'));
  assert.equal(p.kind, 'eip1167_proxy'); assert.equal(p.implementation.toLowerCase(), '0x' + 'be'.repeat(20));
  assert.equal(JSON.parse(bt.evmBytecodeInspect('0xef0100' + '11'.repeat(20))).kind, 'eip7702_delegation');
  assert.equal(JSON.parse(bt.evmBytecodeInspect('0x')).kind, 'empty');
  assert.throws(() => bt.evmBytecodeInspect('0x1'), /odd_length_hex/);
  console.log('ok evm bytecode inspect');
}

{ // evmTypedDataVerify: the EIP-712 specification Mail example
  const td = JSON.stringify({types:{EIP712Domain:[{name:'name',type:'string'},{name:'version',type:'string'},{name:'chainId',type:'uint256'},{name:'verifyingContract',type:'address'}],Person:[{name:'name',type:'string'},{name:'wallet',type:'address'}],Mail:[{name:'from',type:'Person'},{name:'to',type:'Person'},{name:'contents',type:'string'}]},primaryType:'Mail',domain:{name:'Ether Mail',version:'1',chainId:1,verifyingContract:'0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC'},message:{from:{name:'Cow',wallet:'0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826'},to:{name:'Bob',wallet:'0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB'},contents:'Hello, Bob!'}});
  const sig = '0x4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b915621c';
  assert.equal(JSON.parse(bt.evmTypedDataVerify(td)).digest, '0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2');
  assert.equal(JSON.parse(bt.evmTypedDataVerify(td)).verifying_contract, '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC');
  assert.equal(JSON.parse(bt.evmTypedDataVerify(td, sig, '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826')).status, 'valid');
  assert.equal(JSON.parse(bt.evmTypedDataVerify(td, sig, '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB')).status, 'signer_mismatch');
  assert.throws(() => bt.evmTypedDataVerify(td, '0x00'), /signature_not_64_or_65_bytes/);
  console.log('ok evm typed data verify');
}

{ // multisigAddress / taprootMultisigAddress / txPlanResolve / combinePsbts: the scripts/e2e.d/multisig.sh 3-of-5,
  // recorded from the CLIs; the wasm must return the same (one library path), with no private key anywhere.
  const v = JSON.parse(readFileSync(new URL('../../crates/tx/tests/data/multisig-3of5.json', import.meta.url), 'utf8'));
  const strip = (o) => { const { status, tool, ...r } = o; return r; };
  assert.deepEqual(JSON.parse(bt.multisigAddress(3, v.pubkeys, 'bitcoin')), strip(v.multisig));
  assert.deepEqual(JSON.parse(bt.taprootMultisigAddress(3, v.pubkeys, '')), strip(v.taproot_multisig));
  assert.throws(() => bt.multisigAddress(6, v.pubkeys, 'bitcoin'));
  assert.notEqual(JSON.parse(bt.multisigAddress(3, [...v.pubkeys].reverse(), 'bitcoin')).address, v.multisig.address); // order matters
  assert.deepEqual(JSON.parse(bt.txPlanResolve(JSON.stringify(v.plan), JSON.stringify(v.context))), strip(v.resolve));
  assert.throws(() => bt.txPlanResolve('{', '{}'), /bad Plan JSON/);
  assert.throws(() => bt.txPlanResolve(JSON.stringify(v.plan), '[]'), /context/);
  assert.throws(() => bt.txPlanResolve(JSON.stringify({ chain: 'cosmoshub', steps: [] }), '{}'), /family_not_built|unknown|account/);
  assert.deepEqual(JSON.parse(bt.combinePsbts(v.partials)), strip(v.combine));
  assert.throws(() => bt.combinePsbts(v.partials.slice(0, 2)), /not_enough_signatures/);
  assert.throws(() => bt.combinePsbts([]), /no_psbts/);
  assert.throws(() => bt.combinePsbts(['00']), /not_a_psbt/);
  console.log('ok multisig + plan resolve + combine (== CLI)');
}

{ // bech32WitnessProgram: keyless bech32/bech32m witness-program decode == the blocktools-tx library
  // golden vectors (crates/tx/tests/bech32_witness.rs): BIP173 P2WPKH (v0) and BIP350 P2TR (v1).
  const v0 = JSON.parse(bt.bech32WitnessProgram('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'));
  assert.deepEqual(v0, { version: 0, program_hex: '751e76e8199196d454941c45d1b3a323f1433bd6',
    words_hex: '0e140f070d1a001912060b0d081504140311021d030c1d03040f1814060e1e16' });
  const v1 = JSON.parse(bt.bech32WitnessProgram('bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0'));
  assert.deepEqual(v1, { version: 1, program_hex: '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
    words_hex: '0f061f060c1f17191b121d1a18150d000c0a0a1c1d01180b001c0109171f061b0517070211160a191e0a001516051718021e0c00' });
  assert.throws(() => bt.bech32WitnessProgram('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2')); // legacy base58, not segwit
  assert.throws(() => bt.bech32WitnessProgram('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5')); // bad checksum
  console.log('ok bech32WitnessProgram (== library golden)');
}

{ // msgVerify: the Trust Wallet Core signmessage vectors (scripts/e2e.d/twc-message.sh) and the TWC legacy eth vector
  const sig = 'ILH5K7JQLaRGaKGXXH5mYM6FIIy9IWyY4JUPI+PHYY4WaupxUbg+zy0bhBCrDuehy9x4WidwjkRR1GSLnWvOXBo=';
  assert.deepEqual(JSON.parse(bt.msgVerify('19cAJn4Ms8jodBBGtroBNNpCZiHAWGAq7X', 'test signature', sig, false)),
    { status: 'ok', chain: 'btc', address: '19cAJn4Ms8jodBBGtroBNNpCZiHAWGAq7X', recovered: '19cAJn4Ms8jodBBGtroBNNpCZiHAWGAq7X' });
  assert.equal(JSON.parse(bt.msgVerify('1E4T9JZ3mq6cdgiRJEWzHqDXb9t322fE6d', 'test signature', 'H' + sig.slice(1), false)).status, 'ok');
  assert.equal(JSON.parse(bt.msgVerify('1E4T9JZ3mq6cdgiRJEWzHqDXb9t322fE6d', 'test signaturE', 'H' + sig.slice(1), false)).status, 'signer_mismatch');
  const e = JSON.parse(bt.msgVerify('0x0000000000000000000000000000000000000001', 'Foo', '0x21a779d499957e7fd39392d49a079679009e60e492d9654a148829be43d2490736ec72bc4a5644047d979c3cf4ebe2c1c514044cf436b063cb89fc6676be71101b', false));
  assert.equal(e.status, 'signer_mismatch'); assert.equal(e.v, 'legacy'); assert.match(e.recovered, /^0x[0-9a-fA-F]{40}$/);
  assert.equal(JSON.parse(bt.msgVerify(e.recovered, '466f6f', '0x21a779d499957e7fd39392d49a079679009e60e492d9654a148829be43d2490736ec72bc4a5644047d979c3cf4ebe2c1c514044cf436b063cb89fc6676be71101b', true)).status, 'ok');
  assert.throws(() => bt.msgVerify('bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq', 'x', sig, false), /address_not_p2pkh/);
  assert.throws(() => bt.msgVerify('0x0000000000000000000000000000000000000001', 'x', '0x00', false), /signature_not_65_bytes/);
  console.log('ok msg verify');
}

{ // bolt11Decode / bolt11Reencode: the BOLT11 spec test vectors (same as crates/tx/src/bolt11.rs).
  const INV = 'lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql';
  const INV_2500U = 'lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh';
  const d = JSON.parse(bt.bolt11Decode(INV));
  assert.equal(d.network, 'mainnet');
  assert.equal(d.recovered_payee, '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad');
  assert.equal(d.description, 'Please consider supporting this project');
  assert.equal(d.amount_msat, undefined); // no amount in the hrp
  assert.equal(d.tool, undefined); assert.equal(d.status, undefined); // no CLI envelope in the wasm output
  assert.equal(JSON.parse(bt.bolt11Decode(INV_2500U)).amount_msat, '250000000'); // 2500u BTC, decimal string
  const r = JSON.parse(bt.bolt11Reencode(INV));
  assert.equal(r.roundtrip, true); assert.equal(r.reencoded, INV);
  assert.throws(() => bt.bolt11Decode('lnBC1pvjl'), /mixed_case/);
  assert.throws(() => bt.bolt11Decode('bc1qxyz'), /not_a_lightning_invoice/);
  console.log('ok bolt11');
}
