/**
 * S13 GATE -- logout wipes the E2E key IndexedDB BEFORE redirect (H-NEW-1).
 *
 * Run: node encryption/tests/s13_logout_wipe.test.js
 *
 * Background (SECURITY_AUDIT_FINAL.md F-1 / H-NEW-1): AuthService.signOut()
 * cleared in-memory user/session + localStorage auth tokens but NEVER wiped the
 * encryption IndexedDB, so the wrapped identity secret, ratchet states, the
 * decrypted-message-key archive, prekey secrets, session keys AND the at-rest
 * AES-GCM wrap key all survived logout. A local-access attacker could then
 * auto-load the wrap key (no auth gate) and recover the identity secret + full
 * history.
 *
 * Gates:
 *   (1) signOut() invokes KeyStorageService.deleteDatabase() and
 *       BudgetKeyService.clearCache(), and AWAITS the deletion BEFORE the
 *       redirect (window.location.href). Proven by recording a global call
 *       order: deleteDatabase must complete before the navigation is set.
 *   (2) A deleteDatabase() that throws/rejects does NOT block the redirect
 *       (try/catch around the wipe) — availability of logout is preserved.
 *   (3) deleteDatabase uses the whole-DB drop (so wrap_keys is removed too),
 *       NOT clearAll() (which intentionally preserves wrap_keys). We assert
 *       signOut calls deleteDatabase, not clearAll.
 *   (4) Post-wipe semantics: after a real KeyStorageService.deleteDatabase(),
 *       a re-opened DB has no identity record, so getIdentityKeys() returns a
 *       not-found (null) — the secret no longer auto-loads.
 *
 * This gate stubs the browser globals authService.js depends on (window,
 * localStorage, CustomEvent, ...) so it can run under plain node.
 */

const H = require('./_harness.js');
const path = require('path');

// ---------------------------------------------------------------------------
// Minimal browser-global shim so authService.js can be required under node.
// ---------------------------------------------------------------------------
const callOrder = [];

function makeLocalStorage() {
    const map = new Map();
    return {
        get length() { return map.size; },
        key(i) { return Array.from(map.keys())[i] ?? null; },
        getItem(k) { return map.has(k) ? map.get(k) : null; },
        setItem(k, v) { map.set(k, String(v)); },
        removeItem(k) { map.delete(k); },
        clear() { map.clear(); },
    };
}

function installWindow({ deleteDatabaseImpl } = {}) {
    callOrder.length = 0;

    const locationStore = { _href: 'https://example.test/messaging/ui/index.html' };
    const location = {
        origin: 'https://example.test',
        pathname: '/messaging/ui/index.html',
        get href() { return locationStore._href; },
        set href(v) {
            locationStore._href = v;
            callOrder.push('redirect');
        },
    };

    const KeyStorageService = {
        deleteDatabaseCalls: 0,
        clearAllCalls: 0,
        async deleteDatabase() {
            this.deleteDatabaseCalls += 1;
            if (deleteDatabaseImpl) return deleteDatabaseImpl();
            // simulate an async IndexedDB delete that resolves on a later tick
            await new Promise((r) => setTimeout(r, 5));
            callOrder.push('deleteDatabase');
        },
        async clearAll() {
            this.clearAllCalls += 1;
            callOrder.push('clearAll');
        },
    };

    const BudgetKeyService = {
        clearCacheCalls: 0,
        clearCache() {
            this.clearCacheCalls += 1;
            callOrder.push('clearCache');
        },
    };

    const listeners = {};
    const win = {
        location,
        KeyStorageService,
        BudgetKeyService,
        SupabaseConfig: { PROJECT_URL: 'https://proj.supabase.co' },
        ModuleRegistry: { getAllModuleNames: () => ['messaging', 'budget'] },
        localStorage: makeLocalStorage(),
        addEventListener(type, fn) { (listeners[type] = listeners[type] || []).push(fn); },
        removeEventListener() {},
        dispatchEvent(evt) {
            callOrder.push('dispatch:' + evt.type);
            (listeners[evt.type] || []).forEach((fn) => fn(evt));
            return true;
        },
        CustomEvent: class CustomEvent {
            constructor(type, init) { this.type = type; this.detail = init && init.detail; }
        },
    };

    global.window = win;
    global.localStorage = win.localStorage;
    global.CustomEvent = win.CustomEvent;
    global.location = location;
    return win;
}

function loadFreshAuthService() {
    const p = require.resolve('../../shared/services/authService.js');
    delete require.cache[p];
    return require(p);
}

(async () => {
    // ===================================================================
    await H.gate('signOut wipes IndexedDB + clears budget cache BEFORE redirect', async () => {
        const win = installWindow();
        const AuthService = loadFreshAuthService();
        AuthService.client = null; // skip background server sign-out branch
        AuthService.currentUser = { email: 'victim@example.test' };
        AuthService.session = { token: 'x' };

        const res = await AuthService.signOut();

        H.assert(res && res.success === true, 'signOut returns success');
        H.assertEqual(win.KeyStorageService.deleteDatabaseCalls, 1, 'deleteDatabase called exactly once');
        H.assertEqual(win.KeyStorageService.clearAllCalls, 0, 'clearAll NOT used (must drop wrap_keys via deleteDatabase)');
        H.assertEqual(win.BudgetKeyService.clearCacheCalls, 1, 'BudgetKeyService.clearCache called once');

        const delIdx = callOrder.indexOf('deleteDatabase');
        const cacheIdx = callOrder.indexOf('clearCache');
        const redirIdx = callOrder.indexOf('redirect');
        H.assert(delIdx >= 0, 'deleteDatabase actually completed (awaited)');
        H.assert(redirIdx >= 0, 'redirect happened');
        H.assert(delIdx < redirIdx, `deleteDatabase must complete BEFORE redirect (del=${delIdx}, redir=${redirIdx})`);
        H.assert(cacheIdx < redirIdx, `clearCache must run BEFORE redirect (cache=${cacheIdx}, redir=${redirIdx})`);
    });

    // ===================================================================
    await H.gate('a failing deleteDatabase still proceeds to redirect (try/catch)', async () => {
        const win = installWindow({
            deleteDatabaseImpl: async () => {
                callOrder.push('deleteDatabase-threw');
                throw new Error('IndexedDB blocked');
            },
        });
        const AuthService = loadFreshAuthService();
        AuthService.client = null;
        AuthService.currentUser = { email: 'victim@example.test' };

        const res = await AuthService.signOut();
        H.assert(res && res.success === true, 'signOut still returns success after wipe failure');
        H.assert(callOrder.includes('deleteDatabase-threw'), 'deleteDatabase was attempted');
        H.assert(callOrder.includes('redirect'), 'redirect still happened despite wipe failure');
        H.assertEqual(win.BudgetKeyService.clearCacheCalls, 1, 'budget cache still cleared after IndexedDB failure');
    });

    // ===================================================================
    // F-1 regression gate: a deleteDatabase() that NEVER settles (the real
    // hang — e.g. a second tab holds the key DB and onblocked left the promise
    // pending) must NOT strand the redirect. signOut() now Promise.races the wipe
    // against a ~1.5s timeout, so it must still resolve + redirect.
    await H.gate('F-1: signOut does NOT hang when deleteDatabase never settles (blocked/pending)', async () => {
        const win = installWindow({
            // Simulate the hang: a promise that never resolves or rejects.
            deleteDatabaseImpl: () => {
                callOrder.push('deleteDatabase-hangs');
                return new Promise(() => { /* never settles */ });
            },
        });
        const AuthService = loadFreshAuthService();
        AuthService.client = null;
        AuthService.currentUser = { email: 'victim@example.test' };

        const start = Date.now();
        // If signOut still awaited the wipe unconditionally, this would hang forever
        // and the surrounding test runner would time out. The Promise.race timeout
        // (1500ms) must let it resolve.
        const res = await AuthService.signOut();
        const elapsed = Date.now() - start;

        H.assert(res && res.success === true, 'signOut still returns success despite a never-settling deleteDatabase');
        H.assert(callOrder.includes('deleteDatabase-hangs'), 'deleteDatabase was attempted (and hung)');
        H.assert(callOrder.includes('redirect'), 'redirect STILL happened despite the hanging wipe (no logout hang)');
        H.assertEqual(win.BudgetKeyService.clearCacheCalls, 1, 'budget cache still cleared despite the hanging wipe');
        // Guard the timeout actually bounded the wait (well under a hung-forever run).
        H.assert(elapsed < 3000, `signOut resolved within the race timeout window (elapsed=${elapsed}ms)`);
    });

    // ===================================================================
    // F-1 unit gate: the deleteDatabase onblocked handler RESOLVES (no longer
    // leaves the promise pending). Drive the real KeyStorageService.deleteDatabase
    // with a stubbed indexedDB.deleteDatabase that fires onblocked.
    await H.gate('F-1: KeyStorageService.deleteDatabase resolves on onblocked (does not hang)', async () => {
        const KeyStorageService = require('../services/keyStorageService.js');
        // Ensure deleteDatabase tries to close this tab's connection (exercises the
        // close-first path) without a real open DB.
        let closed = false;
        KeyStorageService.db = { close() { closed = true; } };

        const savedIDB = global.indexedDB;
        global.indexedDB = {
            deleteDatabase() {
                const req = {};
                // Fire onblocked on a later tick, like a real blocking second tab.
                setTimeout(() => { if (req.onblocked) req.onblocked(); }, 1);
                return req;
            },
        };
        try {
            // A real hang would make this await never resolve and time out the runner.
            const result = await KeyStorageService.deleteDatabase();
            H.assert(closed, 'deleteDatabase closed this tab\'s connection before deleting (not a blocker itself)');
            H.assert(result && result.blocked === true, 'onblocked resolved with a {blocked:true} status (promise settled, no hang)');
        } finally {
            global.indexedDB = savedIDB;
            KeyStorageService.db = null;
        }
    });

    // ===================================================================
    await H.gate('post-wipe: real deleteDatabase removes the identity record (getIdentityKeys -> not found)', async () => {
        // This exercises the REAL KeyStorageService against fake-indexeddb to prove
        // the post-wipe state: no identity secret auto-loads after a logout wipe.
        let fakeIndexedDB;
        try {
            // fake-indexeddb is optional; if unavailable, skip this sub-gate cleanly.
            const FDBFactory = require(path.resolve(__dirname, '../../node_modules/fake-indexeddb/lib/FDBFactory.js'));
            fakeIndexedDB = new FDBFactory();
        } catch (e) {
            process.stdout.write('  (skipped: fake-indexeddb not installed — node-level post-wipe DB check unavailable)\n');
            return;
        }
        global.indexedDB = fakeIndexedDB;
        const KeyStorageService = require('../services/keyStorageService.js');
        const cfg = { indexedDB: { name: 'MoneyTrackerEncryption' } };
        await KeyStorageService.initialize(cfg);
        const uid = 'user-123';
        const { CryptoPrimitivesService: CP } = H.loadServices();
        const kp = CP.generateKeyPair();
        await KeyStorageService.storeIdentityKeys(uid, kp);
        const before = await KeyStorageService.getIdentityKeys(uid);
        H.assert(before && before.secretKey, 'sanity: identity present before wipe');

        await KeyStorageService.deleteDatabase();
        await KeyStorageService.initialize(cfg); // re-open as a fresh attacker session would
        const after = await KeyStorageService.getIdentityKeys(uid);
        H.assert(!after, 'after deleteDatabase the identity record is gone (no auto-load)');
    });

    H.summary();
})().catch((e) => {
    process.stdout.write('\nUNCAUGHT: ' + (e && e.stack || e) + '\n');
    process.exitCode = 1;
});
