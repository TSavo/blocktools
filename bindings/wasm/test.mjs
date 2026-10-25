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
assert.equal(JSON.parse(bt.supportedChains()).find(c => c.name === 'zec').scope, 'transparent');
const plan = JSON.parse(bt.explainPlan(['--chain', 'btc', '--preset', 'common']));
assert.ok(plan.length > 0 && plan.every(p => p.path.startsWith('m/')));
const b170 = readFileSync(new URL('../../crates/tx/tests/vectors/block170.hex', import.meta.url), 'utf8');
const lines = JSON.parse(bt.decodeTx(b170, 'btc'));
assert.ok(JSON.stringify(lines).includes('f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16'));
const v = JSON.parse(bt.verifyTx(b170, 'btc', ['1Q2TWHE3GMdB6BZKafqwxXtWAWgFt5Jvm3'], ['12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S'], undefined, '', true));
assert.equal(typeof v.ok, 'boolean');
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
  if (JSON.parse(bt.detectAddressInfo("nope")).candidates.length !== 0) throw new Error("detectAddressInfo empty"); }
const det = a => JSON.parse(bt.detectAddress(a)).map(x => x.chain).sort();
assert.deepEqual(det('DFpN6QqFfUm3gKNaxN6tNcab1FArL9cZLE'), ['dgb', 'doge']);
assert.deepEqual(det('t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs'), ['zec']);
assert.equal(bt.convertAddress('1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH', 'zec'), 't1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs');
assert.equal(bt.addressValidate('zec', 't1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs'), 'P2pkh');
const P = JSON.parse(bt.chainParams()); const pr = n => P.find(r => r.name === n);
assert.equal(pr('ppc').decimals, 6); assert.equal(pr('btg').forkid, 79); assert.equal(pr('dash').sweep_build, true);
const dashA = bt.convertAddress('1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH', 'dash');
const sw = JSON.parse(bt.buildUnsignedSweep('dash', JSON.stringify({txid: '0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9', vout: 0, amount: 100000, address: dashA}), dashA, 10));
assert.equal(sw.fee, '1930'); assert.equal(sw.tx_format, 'legacy');
assert.ok(JSON.stringify(JSON.parse(bt.decodeTx(sw.unsigned_tx, 'dash'))).includes(dashA));
assert.throws(() => bt.buildUnsignedSweep('pot', '', dashA, 10));
{ // PoS-nTime (Peercoin): raw tx + prevouts, nTime right after the version
  const ppcA = 'PKGSi8HTQzLx89rkZrRrVkPFjrcSC55NP9';
  const u = JSON.stringify({txid: '0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9', vout: 0, amount: 100000, address: ppcA});
  const p = JSON.parse(bt.buildUnsignedSweepAt('ppc', u, ppcA, 10, 1792800000));
  assert.equal(p.tx_format, 'pos-ntime'); assert.equal(p.psbt, undefined); assert.equal(p.pos_prevouts.length, 1);
  assert.equal(p.unsigned_tx.slice(8, 16), '00f5db6a'); // 1792800000 LE
  assert.throws(() => bt.buildUnsignedSweep('ppc', u, ppcA, 10)); // wasm has no clock: time required
  { // amounts above 2^53 round-trip exactly as strings (RDD whale sweep)
    const rddA = 'RjJ4cn5Bg58D2khGiNRmQW1yWtA6Py9kWa', big = '9007199254740993';
    const r = JSON.parse(bt.buildUnsignedSweepAt('rdd', JSON.stringify({txid: '0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9', vout: 0, amount: big, address: rddA}), rddA, 10, 1792800000));
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
  const O = '9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM', USDC = 'EPjFWdd5AufqSSqeM2qN1xyybapC8G4wEGGkZwyTDt1v', TK = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
  assert.deepEqual(JSON.parse(bt.solAssociatedTokenAddress(O, USDC, '')), {address: '4W6igchc7ZieLsp9grU642c2mBcVSeC9bo5jfn2iBSpe', bump: 255});
  assert.deepEqual(JSON.parse(bt.solFindProgramAddress(JSON.stringify([Buffer.from('vault').toString('hex'), bt.base58Decode(O)]), TK)), {address: 'Duvp5BivpbCj7kPqjzGFUMRuwmv1BBNMp4FvSsLkjZAZ', bump: 254});
  assert.equal(bt.solIsOnCurve(O), true); assert.equal(bt.solIsOnCurve('4W6igchc7ZieLsp9grU642c2mBcVSeC9bo5jfn2iBSpe'), false);
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
  const p = JSON.parse(bt.buildPsbtWithMemo('btc', U, 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu', '', '', 5, Buffer.from('hi').toString('hex')));
  assert.equal(p.psbt, 'cHNidP8BAF8CAAAAAcmXpeVuEEEC+iCcaoUt2QZgogstnDUkI+3OJYV/zTcEAAAAAAD9////AjmEAQAAAAAAFgAUwM681sPTyox13F7GLr5VMw75EOIAAAAAAAAAAARqAmhpAAAAAAABAR+ghgEAAAAAABYAFHUedugZkZbUVJQcRdGzoyPxQzvWAAAA');
  assert.equal(p.fee, '615'); assert.equal(p.outputs[1].address, null);
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
