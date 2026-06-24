/**
 * A15 GATE -- DOWNGRADE / FAIL-OPEN RESISTANCE (pentest hardening regression lock).
 *
 * Run: node encryption/tests/a15_downgrade_resistance.test.js
 *
 * Forcing the error/fallback path must NEVER hand the attacker a WEAKER path. This
 * locks the committed fail-closed posture against three downgrade attempts:
 *
 *   (1) NullEncryptionFacade does NOT silently re-register / accept plaintext.
 *       - Both NullEncryptionFacade.encryptMessage and .decryptMessage are
 *         unconditional throwers ("Encryption required") -- the silent plaintext
 *         primitive (SM-37(a)) is removed, so an accidental wiring cannot downgrade.
 *       - EncryptionModule pins _facade = EncryptionFacade and exposes NO runtime /
 *         server-flag selector for the Null facade. After a fail-closed TRIP
 *         (reset()), getFacade() THROWS rather than falling back to the Null
 *         (plaintext) facade -- the error path is fail-CLOSED, not fail-OPEN.
 *
 *   (2) A version=0 / legacy / unauthenticated ciphertext is NOT silently accepted
 *       where the current path expects authenticated encryption. The real
 *       authenticated primitive is CryptoPrimitivesService.decryptBytes
 *       (XSalsa20-Poly1305 secretbox.open), which THROWS on any input that does not
 *       carry a valid Poly1305 tag -- there is no "plaintext passthrough" / version-0
 *       branch that would accept unauthenticated bytes.
 *
 *   (3) The attachment-metadata bound->legacy RETRY accepts ONLY a recipient-derived
 *       key path. The fallback (AttachmentService._decryptMetadata /
 *       _decryptFileKey) tries the bound (W3-2) KEK then the legacy RK-rooted session
 *       key -- BOTH obtained from KeyManagementService.getSessionKey, i.e. derived
 *       from the recipient's own conversation secret. A FORGED legacy-key blob
 *       (sealed under an ATTACKER key, not either recipient-derived key) authenticates
 *       under NEITHER and is REJECTED -- the legacy back-compat branch is not a
 *       skeleton-key downgrade.
 *
 * These assertions reflect the REAL committed behavior; they are regression locks,
 * not aspirations. All randomness frozen via the S0 RNG seam where used.
 */

const fs = require('fs');
const vm = require('vm');
const H = require('./_harness.js');
const svc = H.loadServices();
const CP = svc.CryptoPrimitivesService;
const KDF = svc.KeyDerivationService;

const NullEncryptionFacade = require('../facade/nullEncryptionFacade.js');
const EncryptionFacade = require('../facade/encryptionFacade.js');
const EncryptionModule = require('../encryptionModule.js');

// Wire the global the facade/module patterns reference (browser pattern under node).
global.EncryptionFacade = EncryptionFacade;
global.NullEncryptionFacade = NullEncryptionFacade;
global.CryptoPrimitivesService = CP;

function enc(str) { return new TextEncoder().encode(str); }

async function assertRejects(promiseFactory, msg) {
    let threw = false;
    try { await promiseFactory(); } catch (e) { threw = true; }
    H.assert(threw, msg || 'expected async function to reject');
}

async function main() {
    // =====================================================================
    // GATE (1a): the NullEncryptionFacade has NO silent plaintext primitive.
    // Forcing it must yield an ERROR, never cleartext (SM-37(a) fail-closed).
    // =====================================================================
    await H.gate('A15 (1a) NullEncryptionFacade NEVER accepts/emits plaintext (always throws)', async () => {
        // encryptMessage: must throw, must not return a plaintext-bearing object.
        await assertRejects(
            () => NullEncryptionFacade.encryptMessage('conv-1', 'secret plaintext', 'recipient-1'),
            'NullEncryptionFacade.encryptMessage throws (no silent plaintext emit)'
        );
        let encErr = null;
        try { await NullEncryptionFacade.encryptMessage('c', 'p', 'r'); } catch (e) { encErr = e; }
        H.assert(encErr instanceof Error, 'encryptMessage error is a real Error');
        H.assertEqual(encErr.message, 'Encryption required', 'encryptMessage fails closed with "Encryption required"');

        // decryptMessage: must throw, must NOT pass content through as decrypted.
        await assertRejects(
            () => NullEncryptionFacade.decryptMessage('conv-1', { ciphertext: 'x' }, 'sender-1'),
            'NullEncryptionFacade.decryptMessage throws (no plaintext passthrough)'
        );
        let decErr = null;
        try { await NullEncryptionFacade.decryptMessage('c', { ciphertext: 'x' }, 's'); } catch (e) { decErr = e; }
        H.assert(decErr instanceof Error, 'decryptMessage error is a real Error');
        H.assertEqual(decErr.message, 'Encryption required', 'decryptMessage fails closed with "Encryption required"');

        // isEncryptionEnabled is honestly false, but that is NOT a usable plaintext path:
        // the only message I/O methods both throw, so a downgrade caller gets nothing.
        H.assertEqual(NullEncryptionFacade.isEncryptionEnabled(), false, 'Null facade reports encryption disabled (honest, but I/O still throws)');
    });

    // =====================================================================
    // GATE (1b): EncryptionModule pins the REAL facade and offers NO selector for
    // the Null (plaintext) facade. A fail-closed trip (reset) does NOT silently
    // re-register a weaker facade -- getFacade() throws instead of falling back.
    // =====================================================================
    await H.gate('A15 (1b) EncryptionModule never re-registers the Null facade after a fail-closed trip', async () => {
        // Simulate the post-initialize, encryption-enabled state WITHOUT the browser
        // CryptoLibraryLoader (which does not exist under node): pin the real facade
        // exactly as initialize() does.
        EncryptionModule.config = { features: {} };
        EncryptionModule.enabled = true;
        EncryptionModule.initialized = true;
        EncryptionModule._facade = EncryptionFacade;

        // Normal state: the facade is the REAL one, never the Null one.
        const facade = EncryptionModule.getFacade();
        H.assert(facade === EncryptionFacade, 'getFacade() returns the real EncryptionFacade');
        H.assert(facade !== NullEncryptionFacade, 'getFacade() is NOT the Null (plaintext) facade');
        H.assert(EncryptionModule.isEnabled() === true, 'module reports enabled');

        // There is NO public API to swap in the Null facade from a flag. getStatus()
        // hard-codes the facade name -- a server-supplied "downgrade" flag has no seam.
        // (EncryptionFacade.getStatus reads KeyManagementService.currentEpoch; stub the
        // minimum so the real getStatus runs without standing up the whole KMS.)
        global.KeyManagementService = { currentEpoch: 0 };
        const status = EncryptionModule.getStatus();
        H.assertEqual(status.facade, 'EncryptionFacade', 'status always reports EncryptionFacade (no Null selection)');
        delete global.KeyManagementService;

        // TRIP fail-closed: reset() (the logout/error path). It must clear the facade,
        // NOT install the Null one.
        EncryptionModule.reset();
        H.assert(EncryptionModule._facade === null, 'after reset, _facade is cleared (not set to Null facade)');
        H.assert(EncryptionModule._facade !== NullEncryptionFacade, 'reset does NOT install the Null facade');
        H.assertEqual(EncryptionModule.isEnabled(), false, 'after reset, module reports disabled');

        // After the trip, asking for the facade FAILS CLOSED (throws) -- it does not
        // silently hand back a weaker (Null/plaintext) facade.
        H.assertThrows(() => EncryptionModule.getFacade(),
            'getFacade() throws after reset (fail-closed; no silent downgrade to Null)');
    });

    // =====================================================================
    // GATE (2): a version=0 / legacy / unauthenticated ciphertext is NOT silently
    // accepted on the authenticated-encryption path (CryptoPrimitivesService).
    // =====================================================================
    await H.gate('A15 (2) authenticated path rejects version=0 / unauthenticated ciphertext', async () => {
        CP.setRandomBytesSource(H.makeDeterministicRng('a15-authpath-seed'));
        const key = CP.randomBytes(32);
        const plaintext = enc('top secret payload');

        // A genuine authenticated ciphertext round-trips.
        const { ciphertext, nonce } = CP.encryptBytes(plaintext, key);
        const recovered = CP.decryptBytes(ciphertext, nonce, key);
        H.assertBytesEqual(recovered, plaintext, 'authenticated ciphertext round-trips');

        // "version=0 / legacy plaintext" forgery #1: hand the would-be plaintext
        // straight into the authenticated open() as if it were a ciphertext. With no
        // Poly1305 tag it MUST be rejected -- there is no plaintext passthrough.
        H.assertThrows(() => CP.decryptBytes(plaintext, nonce, key),
            'raw plaintext (no auth tag) is REJECTED by the authenticated path');

        // Forgery #2: an all-zero "version 0" blob of the same byte length.
        const zeros = new Uint8Array(ciphertext.length);
        H.assertThrows(() => CP.decryptBytes(zeros, nonce, key),
            'all-zero version-0 blob is REJECTED (no unauthenticated acceptance)');

        // Forgery #3: a single flipped tag byte must fail (Poly1305 is enforced).
        const tampered = Uint8Array.from(ciphertext);
        tampered[0] ^= 0x01;
        H.assertThrows(() => CP.decryptBytes(tampered, nonce, key),
            'tampered ciphertext is REJECTED (authentication enforced, not downgraded)');

        // Forgery #4: truncated/empty ciphertext (a "legacy short" record).
        H.assertThrows(() => CP.decryptBytes(new Uint8Array(0), nonce, key),
            'empty/truncated ciphertext is REJECTED');

        CP.resetRandomBytesSource();
    });

    // =====================================================================
    // GATE (3): the attachment bound->legacy RETRY accepts ONLY recipient-derived
    // keys. A FORGED legacy-key metadata blob (sealed under an attacker key) is
    // rejected; only a blob sealed under a recipient-derived key authenticates.
    //
    // We drive the REAL AttachmentService._decryptMetadata / _decryptFileKey retry,
    // mocking window.KeyManagementService.getSessionKey to faithfully reproduce the
    // two production derivations (bound v2 + legacy v1) so the fallback logic under
    // test is the committed one.
    // =====================================================================
    await H.gate('A15 (3) attachment bound->legacy retry rejects a FORGED legacy-key blob', async () => {
        CP.setRandomBytesSource(H.makeDeterministicRng('a15-attach-seed'));

        const conv = 7;
        const path = `${conv}/1700000000-zzzz`;

        // Recipient's invariant attachment root (AK0) and live ratchet root (RK).
        // These are the ONLY secrets the recipient legitimately holds; both
        // getSessionKey derivations are rooted in them.
        const AK0 = CP.randomBytes(32);
        const RK = CP.randomBytes(32);

        // Faithful mirror of KeyManagementService.getSessionKey's two derivations
        // (kept in lockstep with services/keyManagementService.js getSessionKey):
        //   - no context OR no AK0  -> legacy v1 (RK-rooted)
        //   - context + AK0         -> bound   v2 (AK0-rooted, conv+path bound)
        async function boundKEK() {
            const info = `MoneyTracker:Attachment:v2|conv=${conv}|path=${path}`;
            return await KDF._hkdf(AK0, info, 32, AK0);
        }
        async function legacyKEK() {
            return await KDF._hkdf(RK, 'MoneyTracker:Attachment:v1', 32, RK);
        }

        global.KeyManagementService = {
            async getSessionKey(conversationId, context = null) {
                if (!context || !context.attachmentPath) {
                    return await legacyKEK();          // recipient-derived legacy key
                }
                return await boundKEK();               // recipient-derived bound key
            }
        };
        global.window = global; // attachmentService reads window.KeyManagementService / window.CryptoPrimitivesService

        // The attachment service file uses CommonJS module.exports but lives in an
        // ESM ("type":"module") package, so plain require() returns an empty namespace.
        // Load it the same way the harness loads UMD: evaluate the real source as
        // CommonJS in the host realm with window/module wired (so it returns the real
        // object with its methods, against which we drive the committed retry logic).
        const AttachmentService = (() => {
            const file = '/Users/nicholasantoniades/Documents/GitHub/messaging_app/messaging/services/attachmentService.js';
            const m = { exports: {} };
            const src = fs.readFileSync(file, 'utf8');
            const fn = vm.runInThisContext('(function(module, exports, window){' + src + '\n})', { filename: file });
            fn(m, m.exports, global.window);
            return m.exports;
        })();
        H.assert(typeof AttachmentService._decryptMetadata === 'function', 'loaded the real AttachmentService (has _decryptMetadata)');

        const realLegacyKey = await legacyKEK();
        const realBoundKey = await boundKEK();
        const meta = { file_name: 'spy.pdf', mime_type: 'application/pdf', file_size: 1234 };

        // Helper: seal a metadata blob under an ARBITRARY key (mirrors _encryptMetadata).
        function sealMeta(metaObj, key) {
            const pt = CP.encodeUTF8(JSON.stringify(metaObj));
            const { ciphertext, nonce } = CP.encryptBytes(pt, key);
            return {
                encryptedMetadata: btoa(String.fromCharCode(...ciphertext)),
                metadataNonce: btoa(String.fromCharCode(...nonce))
            };
        }

        // (3a) SANITY: a blob legitimately sealed under the recipient-derived LEGACY
        // key DOES decrypt via the legacy fallback (no attachmentPath -> bound skipped).
        const legitLegacyBlob = sealMeta(meta, realLegacyKey);
        const okLegacy = await AttachmentService._decryptMetadata(
            legitLegacyBlob.encryptedMetadata, legitLegacyBlob.metadataNonce, conv, null
        );
        H.assertEqual(okLegacy.file_name, 'spy.pdf', 'legit legacy-key blob decrypts via the legacy path (back-compat preserved)');

        // (3b) SANITY: a blob sealed under the recipient-derived BOUND key decrypts via
        // the bound path (attachmentPath supplied).
        const legitBoundBlob = sealMeta(meta, realBoundKey);
        const okBound = await AttachmentService._decryptMetadata(
            legitBoundBlob.encryptedMetadata, legitBoundBlob.metadataNonce, conv, path
        );
        H.assertEqual(okBound.file_name, 'spy.pdf', 'legit bound-key blob decrypts via the bound path');

        // (3c) THE ATTACK: a FORGED blob sealed under an ATTACKER key (NOT either
        // recipient-derived key). The retry tries bound (fails auth) then legacy
        // (fails auth) and MUST throw -- the legacy branch is not a skeleton key.
        const attackerKey = CP.randomBytes(32);
        H.assert(!Buffer.from(attackerKey).equals(Buffer.from(realLegacyKey)), 'attacker key != recipient legacy key');
        H.assert(!Buffer.from(attackerKey).equals(Buffer.from(realBoundKey)), 'attacker key != recipient bound key');
        const forgedBlob = sealMeta({ file_name: 'forged.exe', mime_type: 'text/html', file_size: 9 }, attackerKey);

        // With attachmentPath: bound key tried first (fails), then legacy (fails) -> throw.
        await assertRejects(
            () => AttachmentService._decryptMetadata(forgedBlob.encryptedMetadata, forgedBlob.metadataNonce, conv, path),
            'FORGED attacker-key metadata blob is REJECTED on the bound->legacy retry (with path)'
        );
        // Without attachmentPath: straight to legacy (fails) -> throw. The forged
        // legacy-key blob is NOT accepted just because it claims to be "legacy".
        await assertRejects(
            () => AttachmentService._decryptMetadata(forgedBlob.encryptedMetadata, forgedBlob.metadataNonce, conv, null),
            'FORGED attacker-key metadata blob is REJECTED on the legacy-only path (no path)'
        );

        // (3d) SAME guarantee for the file-key unwrap retry (_decryptFileKey): a file
        // key wrapped under the attacker key is rejected by the bound->legacy retry,
        // while a legit recipient-derived wrap unwraps.
        const fileKey = CP.randomBytes(32);
        function wrapKey(fk, kek) {
            const { ciphertext, nonce } = CP.encryptBytes(fk, kek);
            return {
                encryptedKey: btoa(String.fromCharCode(...ciphertext)),
                nonce: btoa(String.fromCharCode(...nonce))
            };
        }
        const legitWrap = wrapKey(fileKey, realBoundKey);
        const recovered = await AttachmentService._decryptFileKey(
            legitWrap.encryptedKey, legitWrap.nonce, conv, path
        );
        H.assertBytesEqual(recovered, fileKey, 'legit recipient-wrapped file key unwraps via the bound path');

        const forgedWrap = wrapKey(fileKey, attackerKey);
        await assertRejects(
            () => AttachmentService._decryptFileKey(forgedWrap.encryptedKey, forgedWrap.nonce, conv, path),
            'FORGED attacker-wrapped file key is REJECTED on the bound->legacy retry'
        );
        await assertRejects(
            () => AttachmentService._decryptFileKey(forgedWrap.encryptedKey, forgedWrap.nonce, conv, null),
            'FORGED attacker-wrapped file key is REJECTED on the legacy-only path'
        );

        delete global.KeyManagementService;
        CP.resetRandomBytesSource();
    });

    H.summary();
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
