# Security Audit — Wave N (Adversarial)

**Scope:** auth_db (identity + E2E crypto), secure_db (messaging schema/RLS), payments_app (Stripe edge functions), messaging_app (messenger client), money_tracker (budget client + budget E2E). Shared Supabase (Postgres + RLS + Auth + Realtime + Storage + Edge Functions).
**Attacker models in scope:** malicious authenticated user, malicious peer, MITM, and a curious/compromised server (the zero-knowledge claim must hold against the server itself).
**Mandate:** report only NEW, adversarially-verified, exploitable findings beyond prior waves. Anything materially equivalent to the prior-wave findings (C-1, H-1..H-6, M-2..M-5, the 20-byte recovery-key testing value) is explicitly out of scope.
**Constraint:** READ-ONLY audit. No files modified.

---

## 1. Summary

**NEW issues confirmed this wave: 0.**

This wave produced **zero new adversarially-verified findings** beyond those already confirmed in prior waves. The set of verified-real findings handed to this report was empty, and no uncertain items were carried forward for human review.

**Posture delta:** No change. The platform's verified risk surface remains exactly the prior-wave backlog — the open CRITICAL/HIGH items (notably C-1 `data_shares` UPDATE missing `WITH CHECK`, H-1 unpinned responder X3DH identity key, H-3 client-only entitlement enforcement, H-4 unbound budget-DEK seal) continue to dominate the risk profile and remain the correct priority. No regression and no new exposure was introduced or discovered in this wave's coverage.

This is a clean-but-not-complete result. "Zero new findings" reflects the verified inputs available to this wave — it is **not** an assertion that the platform is now free of undiscovered vulnerabilities. The prior-wave open items remain unremediated and are the governing risk.

---

## 2. Findings by Severity

### CRITICAL
None new this wave.

### HIGH
None new this wave.

### MEDIUM
None new this wave.

### LOW
None new this wave.

All previously confirmed findings (C-1; H-1 through H-6; M-2 through M-5; the recovery-key 20-byte testing value) are intentionally excluded as out-of-scope duplicates per the wave mandate. Their remediation status is unchanged and they remain open.

---

## 3. Uncertain Items for Human Review

None. No candidate findings reached the "uncertain / needs human verification" threshold in this wave.

---

## 4. Prioritized Remediation

No new remediation work originates from this wave. The prioritized backlog is unchanged and is governed entirely by the prior waves' confirmed findings. Recommended order (carried forward, not new):

1. **C-1** — `data_shares` UPDATE policy missing `WITH CHECK` (privilege/row-ownership integrity).
2. **H-1** — responder X3DH trusts unpinned X25519 identity key (MITM / impersonation against the E2E guarantee).
3. **H-3** — entitlement enforcement client-only; no server gate on messages, no trial-expiry (server-side bypass).
4. **H-4** — budget-DEK seal unpinned/unauthenticated/unbound (zero-knowledge violation against a compromised server).
5. **H-2, H-5, H-6** and the **M-series** — per their prior-wave severity.
6. Replace the 20-byte testing recovery-key value before any production exposure.

---

*Wave N adds no new items to this list. Treat the prior-wave backlog as the active remediation plan.*
