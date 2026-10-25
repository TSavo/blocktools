// Loads the browser build (pkg/web, wasm-bindgen --target web) under Node: init with the wasm bytes,
// then check it exposes exactly the pkg/node function set and answers like it.
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import init, * as web from './pkg/web/blocktools_wasm.js';
import * as node from './pkg/node/blocktools_wasm.js';
await init({ module_or_path: readFileSync(new URL('./pkg/web/blocktools_wasm_bg.wasm', import.meta.url)) });
const fns = (m) => Object.keys(m).filter((k) => typeof m[k] === 'function' && !k.startsWith('__wbindgen') && k !== 'default' && k !== 'initSync').sort();
assert.deepEqual(fns(web), fns(node.default ?? node).filter((k) => k !== 'initSync'));
assert.equal(web.validateAddress('btc', 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu'), 'SegwitV0');
assert.equal(web.solAnchorDiscriminator('initialize'), 'afaf6d1f0d989bed');
assert.equal(web.version(), (node.default ?? node).version());
console.log(`wasm web ok (${fns(web).length} exports)`);
