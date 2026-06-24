# Vendored: hash-wasm (Argon2id)

Memory-hard **Argon2id** KDF for the at-rest password/backup/recovery wrap key
(L-3 / CRYPTO_REVIEW_BRIEF HIGH). We NEVER hand-roll Argon2id — this is a vetted,
WASM-backed implementation that runs identically in the browser and in node.

## Provenance

| field      | value |
|------------|-------|
| package    | [`hash-wasm`](https://www.npmjs.com/package/hash-wasm) |
| version    | **4.12.0** |
| license    | MIT (see `LICENSE`) |
| file       | `argon2.umd.min.js` — the per-algorithm UMD build (Argon2 only, ~29 KB) |
| obtained   | `npm pack hash-wasm` → `dist/argon2.umd.min.js` |

`argon2.umd.min.js` is **self-contained**: the WebAssembly module is embedded as
base64 inside the file, so there is no separate `.wasm` to fetch and no network
dependency at runtime. It exposes `argon2id`, `argon2i`, `argon2d`, and
`argon2Verify`.

## Integrity (SRI)

```
sha384-tP0Wy54CKmng7i9EoTlPySD0hBx6Octj0VS6MfwlnUu111MPa+JLm0CCbep6XJ1W
sha256  dcec617a2e1b700fa132d1583a186cb70611113395e869f2dd6cc82b415d3094
```

## Loading

### Browser (`<script>` + window global — no bundler, no npm runtime dep)

Add this ONE line on any page that wraps/unwraps an identity-key backup, before
`passwordCryptoService.js` is used (path is relative to the page, mirroring the
nacl includes in `shared/vendor/crypto/`):

```html
<script src="../../shared/vendor/hash-wasm/argon2.umd.min.js"></script>
```

It defines `window.hashwasm` (with `window.hashwasm.argon2id`). The crypto
service auto-detects it; no further wiring is needed. Optionally pin integrity:

```html
<script src="../../shared/vendor/hash-wasm/argon2.umd.min.js"
        integrity="sha384-tP0Wy54CKmng7i9EoTlPySD0hBx6Octj0VS6MfwlnUu111MPa+JLm0CCbep6XJ1W"
        crossorigin="anonymous"></script>
```

### Node (tests / server tooling)

`require('../../shared/vendor/hash-wasm/argon2.umd.min.js')` returns the same
object (CommonJS branch of the UMD). `PasswordCryptoService._getHashWasm()` does
this automatically as a fallback; tests may also inject it explicitly with
`PasswordCryptoService.setHashWasm(require('.../argon2.umd.min.js'))`.

## Parameters

OWASP "Password Storage" guidance: **m = 64 MiB (65536 KiB), t = 3, p = 1**,
hashLength = 32 bytes (AES-256 key), 16-byte random salt. The params are stored
IN each backup's salt envelope, so a future tune stays forward/backward
compatible. Never drop below the OWASP floor (m ≥ 19 MiB, t ≥ 2). See
`encryption/services/passwordCryptoService.js` `_getArgon2Params`.
