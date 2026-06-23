/**
 * Test harness for the encryption services under node (no browser, no DB).
 *
 * Responsibilities:
 *   - Load the vendored TweetNaCl (nacl-fast + nacl-util) from the sibling app
 *     repo using vm.runInThisContext, so nacl shares the HOST realm's typed
 *     arrays (otherwise nacl's `instanceof Uint8Array` checks fail).
 *   - Provide global `crypto` (node:crypto.webcrypto) for WebCrypto HKDF used by
 *     keyDerivationService.
 *   - Wire the loaded nacl into CryptoPrimitivesService (bypassing the
 *     <script>/CDN CryptoLibraryLoader, which does not exist under node).
 *   - Expose a deterministic RNG factory for the frozen-seed FS/PCS gates.
 *
 * This is the "NaCl shim + seeded RNG hook" the design (FORWARD_SECRECY_DESIGN
 * section 8) calls for. It does NOT touch production randomness defaults.
 */

const fs = require('fs');
const vm = require('vm');
const path = require('path');
const nodeCrypto = require('crypto');

// WebCrypto must be a global for keyDerivationService._hkdf (crypto.subtle).
if (typeof global.crypto === 'undefined') {
    global.crypto = nodeCrypto.webcrypto;
}

// ---- locate the vendored TweetNaCl ----------------------------------------
// auth_db is a library consumed by sibling apps; the vendored nacl lives there.
const VENDOR_CANDIDATES = [
    path.resolve(__dirname, '../../../messaging_app/shared/vendor/crypto'),
    path.resolve(__dirname, '../../../money_tracker/shared/vendor/crypto'),
    path.resolve(__dirname, '../../shared/vendor/crypto'),
];

function findVendorDir() {
    for (const dir of VENDOR_CANDIDATES) {
        if (fs.existsSync(path.join(dir, 'nacl-fast.min.js')) &&
            fs.existsSync(path.join(dir, 'nacl-util.min.js'))) {
            return dir;
        }
    }
    throw new Error(
        'Could not locate vendored TweetNaCl (nacl-fast.min.js + nacl-util.min.js). ' +
        'Looked in:\n  ' + VENDOR_CANDIDATES.join('\n  ')
    );
}

/**
 * Load a UMD module file into the HOST realm (so typed arrays are shared).
 */
function loadUMD(file) {
    const m = { exports: {} };
    const src = fs.readFileSync(file, 'utf8');
    const wrapper = '(function(module, exports, Buffer, crypto){' + src + '\n})';
    const fn = vm.runInThisContext(wrapper, { filename: file });
    fn(m, m.exports, Buffer, global.crypto);
    return m.exports;
}

let _nacl = null;
function loadNacl() {
    if (_nacl) return _nacl;
    const dir = findVendorDir();
    const nacl = loadUMD(path.join(dir, 'nacl-fast.min.js'));
    nacl.util = loadUMD(path.join(dir, 'nacl-util.min.js'));
    // nacl ships with no PRNG by default; give it the secure node one so the
    // PRODUCTION default path (when no RNG source is injected) still works.
    nacl.setPRNG((x, n) => {
        const b = nodeCrypto.randomBytes(n);
        for (let i = 0; i < n; i++) x[i] = b[i];
    });
    _nacl = nacl;
    return nacl;
}

/**
 * Load + initialize the encryption services for node testing.
 * Returns { nacl, CryptoPrimitivesService, KeyDerivationService, DoubleRatchetService? }.
 */
function loadServices() {
    const nacl = loadNacl();

    const CryptoPrimitivesService = require('../services/cryptoPrimitivesService.js');
    const KeyDerivationService = require('../services/keyDerivationService.js');

    // Make KeyDerivationService a global too (services reference each other as
    // globals in the browser); harmless under node.
    global.KeyDerivationService = KeyDerivationService;
    global.CryptoPrimitivesService = CryptoPrimitivesService;

    // Wire nacl in directly, bypassing CryptoLibraryLoader (CDN/<script>).
    CryptoPrimitivesService.nacl = nacl;
    CryptoPrimitivesService.initialized = true;
    CryptoPrimitivesService._config = null;

    KeyDerivationService.initialize({}); // uses defaults: SHA-256, "MoneyTracker"

    const out = { nacl, CryptoPrimitivesService, KeyDerivationService };

    // DoubleRatchetService is optional (only present after S1).
    try {
        const DoubleRatchetService = require('../services/doubleRatchetService.js');
        global.DoubleRatchetService = DoubleRatchetService;
        out.DoubleRatchetService = DoubleRatchetService;
    } catch (e) { /* not present yet */ }

    return out;
}

/**
 * Deterministic counter-based random-bytes source for frozen-seed gates.
 *
 * Produces a reproducible stream by hashing (seedLabel || blockCounter) with
 * SHA-256 and concatenating blocks. The exact bytes are an implementation
 * detail of the gate -- what matters is that the SAME seedLabel yields the SAME
 * stream every run, making ephemeral keygen and secretbox nonces reproducible.
 *
 * @param {string} seedLabel - label that fully determines the stream
 * @returns {function(number): Uint8Array}
 */
function makeDeterministicRng(seedLabel) {
    let counter = 0;
    let buffer = Buffer.alloc(0);
    function refill() {
        const h = nodeCrypto.createHash('sha256');
        h.update('FS-GATE-RNG|' + seedLabel + '|' + counter);
        counter += 1;
        buffer = Buffer.concat([buffer, h.digest()]);
    }
    return function randomBytes(length) {
        while (buffer.length < length) refill();
        const out = buffer.subarray(0, length);
        buffer = buffer.subarray(length);
        return new Uint8Array(out); // host Uint8Array
    };
}

// ---- tiny assertion / test runner ----------------------------------------
let _pass = 0;
let _fail = 0;
const _failures = [];

function assert(cond, msg) {
    if (!cond) {
        _fail += 1;
        _failures.push(msg || 'assertion failed');
        throw new Error('ASSERT FAILED: ' + (msg || ''));
    }
    _pass += 1;
}

function assertEqual(actual, expected, msg) {
    assert(actual === expected, `${msg || ''} (expected ${expected}, got ${actual})`);
}

function assertBytesEqual(a, b, msg) {
    const ba = Buffer.from(a), bb = Buffer.from(b);
    assert(ba.equals(bb), `${msg || ''} (\n  expected ${bb.toString('hex')}\n  got      ${ba.toString('hex')})`);
}

function assertThrows(fn, msg) {
    let threw = false;
    try { fn(); } catch (e) { threw = true; }
    assert(threw, msg || 'expected function to throw');
}

function gate(name, fn) {
    process.stdout.write(`\n=== GATE: ${name} ===\n`);
    return Promise.resolve()
        .then(fn)
        .then(() => { process.stdout.write(`--- GATE PASSED: ${name} ---\n`); })
        .catch((e) => {
            process.stdout.write(`*** GATE FAILED: ${name}: ${e.message} ***\n`);
            throw e;
        });
}

function summary() {
    process.stdout.write(`\n========================================\n`);
    process.stdout.write(`TOTAL ASSERTIONS: ${_pass} passed, ${_fail} failed\n`);
    if (_fail > 0) {
        process.stdout.write('FAILURES:\n  - ' + _failures.join('\n  - ') + '\n');
        process.exitCode = 1;
    } else {
        process.stdout.write('ALL ASSERTIONS PASSED\n');
    }
    process.stdout.write(`========================================\n`);
}

function toHex(bytes) {
    return Buffer.from(bytes).toString('hex');
}

module.exports = {
    loadNacl,
    loadServices,
    makeDeterministicRng,
    assert,
    assertEqual,
    assertBytesEqual,
    assertThrows,
    gate,
    summary,
    toHex,
};
