# End-to-End Encryption Security Architecture

## Overview

Money Tracker uses **end-to-end encryption (E2E)** for premium user messages. Messages are encrypted on the sender's device and can only be decrypted by the intended recipient. The server never has access to plaintext messages or private keys.

---

## Cryptographic Primitives

| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| Key Pair Generation | **X25519** | Elliptic curve key pairs for ECDH |
| Key Agreement | **ECDH** (Curve25519) | Derive shared secrets between parties |
| Key Derivation | **HKDF-SHA256** | Derive message keys from shared secrets |
| Message Encryption | **XSalsa20-Poly1305** | Authenticated encryption with 24-byte nonce |
| Password Encryption | **AES-256-GCM** + **PBKDF2** | Backup key protection |

---

## Key Hierarchy

```
┌─────────────────────────────────────────────────────────────────┐
│                     IDENTITY KEY PAIR                           │
│            (X25519: 32-byte public + 32-byte secret)            │
│                 Generated once per user                         │
│                  Stored in IndexedDB                            │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            │ ECDH with recipient's public key
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                     SHARED SECRET                               │
│               (32 bytes from X25519 ECDH)                       │
│              Unique per sender-recipient pair                   │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            │ HKDF with epoch
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                     SESSION KEY                                 │
│                (32 bytes, epoch-specific)                       │
│             Derived per conversation + epoch                    │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            │ HKDF with message counter
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                     MESSAGE KEY                                 │
│              (32 bytes, unique per message)                     │
│          Used once for XSalsa20-Poly1305 encryption             │
└─────────────────────────────────────────────────────────────────┘
```

---

## Key Generation Flow

```
┌──────────────┐
│  New User    │
│  Registers   │
└──────┬───────┘
       │
       ▼
┌──────────────────────────────────────┐
│  1. Generate X25519 Key Pair         │
│     - publicKey  (32 bytes)          │
│     - secretKey  (32 bytes)          │
└──────┬───────────────────────────────┘
       │
       ├──────────────────────────────────────────┐
       │                                          │
       ▼                                          ▼
┌──────────────────────┐           ┌──────────────────────────────┐
│  Store in IndexedDB  │           │  Publish to Database         │
│  (secret + public)   │           │  (public key only)           │
│  [LOCAL ONLY]        │           │  Table: identity_keys        │
└──────────────────────┘           └──────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────┐
│  2. Create Password-Protected Backup │
│     - PBKDF2(password) → backup_key  │
│     - AES-GCM(backup_key, secretKey) │
│     - Store encrypted in database    │
└──────────────────────────────────────┘
```

---

## Key Exchange (Session Establishment)

When Alice wants to message Bob:

```
     ALICE                                           BOB
       │                                              │
       │  1. Fetch Bob's public key from database     │
       │◄─────────────────────────────────────────────│
       │                                              │
       ▼                                              │
┌─────────────────────────┐                           │
│ 2. ECDH Key Agreement   │                           │
│    sharedSecret =       │                           │
│    X25519(Alice.secret, │                           │
│           Bob.public)   │                           │
└─────────────────────────┘                           │
       │                                              │
       ▼                                              │
┌─────────────────────────┐                           │
│ 3. Derive Session Key   │                           │
│    sessionKey =         │                           │
│    HKDF(sharedSecret,   │                           │
│         epoch)          │                           │
└─────────────────────────┘                           │
       │                                              │
       │  Session established                         │
       │  (Bob derives same key using                 │
       │   his secretKey + Alice's publicKey)         │
       └──────────────────────────────────────────────┘
```

**Key Property**: ECDH is symmetric - both parties derive the **same shared secret**:
- Alice: `X25519(Alice.secret, Bob.public)` = shared_secret
- Bob: `X25519(Bob.secret, Alice.public)` = shared_secret

---

## Message Encryption Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    SENDER (ENCRYPT)                             │
└─────────────────────────────────────────────────────────────────┘

     ┌──────────────┐
     │  Plaintext   │
     │   Message    │
     └──────┬───────┘
            │
            ▼
┌───────────────────────────────────────┐
│  1. Get/Derive Session Key            │
│     (from IndexedDB or ECDH)          │
└───────────────────────────────────────┘
            │
            ▼
┌───────────────────────────────────────┐
│  2. Derive Message Key via HKDF       │
│     info = "MessageKey:{epoch}:{n}"   │
│     messageKey = HKDF(sessionKey,     │
│                       info)           │
└───────────────────────────────────────┘
            │
            ▼
┌───────────────────────────────────────┐
│  3. Generate Random Nonce (24 bytes)  │
└───────────────────────────────────────┘
            │
            ▼
┌───────────────────────────────────────┐
│  4. Encrypt with XSalsa20-Poly1305    │
│     ciphertext = encrypt(plaintext,   │
│                          nonce,       │
│                          messageKey)  │
└───────────────────────────────────────┘
            │
            ▼
┌───────────────────────────────────────┐
│  5. Send to Server:                   │
│     - encrypted_content (ciphertext)  │
│     - encryption_nonce                │
│     - message_counter (n)             │
│     - key_epoch                       │
└───────────────────────────────────────┘
```

---

## Message Decryption Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    RECIPIENT (DECRYPT)                          │
└─────────────────────────────────────────────────────────────────┘

┌───────────────────────────────────────┐
│  Receive from Server:                 │
│  - encrypted_content                  │
│  - encryption_nonce                   │
│  - message_counter                    │
│  - key_epoch                          │
└───────────────────────────────────────┘
            │
            ▼
┌───────────────────────────────────────┐
│  1. Get Session Key for Epoch         │
│     (from IndexedDB cache or          │
│      re-derive using historical key)  │
└───────────────────────────────────────┘
            │
            ▼
┌───────────────────────────────────────┐
│  2. Derive Same Message Key           │
│     info = "MessageKey:{epoch}:{n}"   │
│     messageKey = HKDF(sessionKey,     │
│                       info)           │
└───────────────────────────────────────┘
            │
            ▼
┌───────────────────────────────────────┐
│  3. Decrypt with XSalsa20-Poly1305    │
│     plaintext = decrypt(ciphertext,   │
│                         nonce,        │
│                         messageKey)   │
│                                       │
│     (Authentication tag verified      │
│      automatically - fails if tamper) │
└───────────────────────────────────────┘
            │
            ▼
     ┌──────────────┐
     │  Plaintext   │
     │   Message    │
     └──────────────┘
```

---

## Key Regeneration & Historical Keys

When a user regenerates their identity keys (security refresh):

```
┌──────────────────────────────────────────────────────────────────┐
│                    KEY REGENERATION FLOW                         │
└──────────────────────────────────────────────────────────────────┘

┌─────────────────────────────┐
│  User triggers regeneration │
└─────────────────────────────┘
            │
            ▼
┌───────────────────────────────────────┐
│  1. Archive Current Public Key        │
│     - Store in public_key_history     │
│     - Record current epoch number     │
│     - Enables old message decryption  │
└───────────────────────────────────────┘
            │
            ▼
┌───────────────────────────────────────┐
│  2. Generate New X25519 Key Pair      │
│     - New publicKey + secretKey       │
│     - Increment epoch counter         │
└───────────────────────────────────────┘
            │
            ▼
┌───────────────────────────────────────┐
│  3. Update Storage                    │
│     - IndexedDB: new keys             │
│     - Database: new public key        │
│     - Database: increment epoch       │
└───────────────────────────────────────┘
            │
            ▼
┌───────────────────────────────────────┐
│  4. Re-encrypt Session Backups        │
│     - Decrypt with old backup key     │
│     - Re-encrypt with new backup key  │
└───────────────────────────────────────┘


┌──────────────────────────────────────────────────────────────────┐
│                 DECRYPTING OLD MESSAGES                          │
└──────────────────────────────────────────────────────────────────┘

When decrypting a message from epoch N (and current epoch is M > N):

1. Message contains: { ciphertext, nonce, counter, epoch: N }
2. Lookup sender's public key at epoch N from public_key_history
3. Derive shared secret: ECDH(my_secretKey, sender_publicKey_epochN)
4. Derive session key: HKDF(sharedSecret, epoch: N)
5. Derive message key: HKDF(sessionKey, counter)
6. Decrypt message
```

---

## Multi-Device Support

```
┌──────────────────────────────────────────────────────────────────┐
│                    DEVICE PAIRING FLOW                           │
└──────────────────────────────────────────────────────────────────┘

     PRIMARY DEVICE                         NEW DEVICE
           │                                    │
           │                                    │
           │  User logs in on new device        │
           │                                    │
           │                                    ▼
           │                          ┌─────────────────────┐
           │                          │ No local keys found │
           │                          │ Check database...   │
           │                          └─────────────────────┘
           │                                    │
           │                                    ▼
           │                          ┌─────────────────────┐
           │                          │ Found backup!       │
           │                          │ Prompt for password │
           │                          └─────────────────────┘
           │                                    │
           │                                    ▼
           │                          ┌─────────────────────┐
           │                          │ Decrypt backup:     │
           │                          │ 1. PBKDF2(password) │
           │                          │    → backup_key     │
           │                          │ 2. AES-GCM decrypt  │
           │                          │    → secretKey      │
           │                          └─────────────────────┘
           │                                    │
           │                                    ▼
           │                          ┌─────────────────────┐
           │                          │ Store in IndexedDB  │
           │                          │ Sync session keys   │
           │                          │ from database       │
           │                          └─────────────────────┘
           │                                    │
           │         Both devices now          │
           │◄──────── synchronized ───────────►│
           │                                    │
```

---

## Security Properties

| Property | How It's Achieved |
|----------|-------------------|
| **Confidentiality** | XSalsa20-Poly1305 encryption; only key holders can decrypt |
| **Integrity** | Poly1305 authentication tag; tampering detected |
| **Forward Secrecy** | Per-message keys derived via HKDF with counter |
| **Key Compromise Recovery** | Epoch-based key regeneration; old messages stay readable |
| **Server Zero-Knowledge** | Server stores only encrypted content + public keys |
| **Multi-Device Support** | Password-encrypted backups in database |

---

## Data Flow Summary

```
┌─────────────────────────────────────────────────────────────────┐
│                        LOCAL STORAGE                            │
│                        (IndexedDB)                              │
├─────────────────────────────────────────────────────────────────┤
│  identity_keys:     { userId, publicKey, secretKey }            │
│  session_keys:      { conversationId, epoch, sharedSecret }     │
│  historical_keys:   { userId, epoch, publicKey }                │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ Encrypted backup
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     DATABASE (Supabase)                         │
├─────────────────────────────────────────────────────────────────┤
│  identity_keys:           Public key only + epoch               │
│  public_key_history:      Historical public keys per epoch      │
│  identity_key_backups:    Password-encrypted private key        │
│  conversation_session_keys: Backup-key encrypted session keys   │
│  messages:                Encrypted content + metadata          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Safety Number Verification

Users can verify their encryption keys match by comparing safety numbers:

```
1. Concatenate both public keys (sorted)
2. SHA-512 hash the concatenation
3. Convert first 30 bytes to decimal digits
4. Display as groups: "12345 67890 12345 ..."
```

Both users should see **identical** safety numbers. A mismatch indicates:
- Potential man-in-the-middle attack
- Key mismatch (one user has wrong key)

---

## Premium Feature Gating

```javascript
// Facade pattern for optional encryption

if (user.subscription === 'premium') {
    // Full encryption enabled
    EncryptionFacade.encryptMessage(...)
} else {
    // Plaintext messaging (no encryption)
    NullEncryptionFacade.encryptMessage(...) // Returns plaintext
}
```

Free users: Messages stored as plaintext (`content` column)
Premium users: Messages stored encrypted (`encrypted_content` column)

---

**Library**: TweetNaCl.js (audited, constant-time implementation)
**Standards**: X25519 (RFC 7748), HKDF (RFC 5869), XSalsa20-Poly1305
