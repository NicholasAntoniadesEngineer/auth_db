#!/usr/bin/env node
// ============================================================================
// rls_abuse_probe.mjs — live RLS / PostgREST cross-user abuse probe
// ============================================================================
// WHAT THIS IS
//   A runnable, dependency-free (Node >= 18, global fetch) DAST probe that attacks
//   the LIVE PostgREST REST API the way a real attacker with one stolen/owned
//   account would: it takes ONE attacker JWT and a SECOND victim user-id, then
//   tries to read/write the victim's rows and to abuse the SECURITY DEFINER RPCs
//   across the user boundary. For each attempt it prints PASS (server BLOCKED the
//   cross-user action — RLS held) or FAIL (server ALLOWED it — RLS hole).
//
//   It is GROUNDED in the real schema:
//     * table/column names: money_tracker/database/setup/fresh-install-complete.sql,
//       secure_db/sql/complete-setup.sql, payments_app/backend/sql/complete-setup.sql,
//       auth_db/backend/sql/complete-setup.sql
//     * REST shape: auth_db/database/services/databaseService.js
//         - ${SUPABASE_URL}/rest/v1/<table>?<col>=eq.<val>   (PostgREST filters)
//         - headers: apikey, Authorization: Bearer <jwt>, Prefer
//         - RPC:     ${SUPABASE_URL}/rest/v1/rpc/<fn>  (POST, JSON body)
//
//   This probe is INTENTIONALLY read-mostly. The WRITE attempts target the
//   ATTACKER's own rows where a write would be legitimate, OR the VICTIM's rows
//   where a write MUST be blocked. It does NOT delete the victim's data on a hole;
//   it reports the hole. (A real pentest would then weaponise it — that is theirs
//   to do, deliberately, with consent.)
//
// ----------------------------------------------------------------------------
// HOW TO GET TWO TEST JWTs  (you need: 1 attacker access token + the victim's id)
// ----------------------------------------------------------------------------
//   Create TWO throwaway accounts in the app (attacker@example.com,
//   victim@example.com). For EACH, in the browser console on the deployed site
//   AFTER logging in:
//
//     const { data } = await window.supabase.auth.getSession();
//     console.log('access_token', data.session.access_token);
//     console.log('user_id',      data.session.user.id);
//
//   (or DevTools > Application > Local Storage > the `sb-<ref>-auth-token` entry;
//    the JSON has .access_token and .user.id)
//
//   Then have the VICTIM seed a little data first (one message to anyone, one
//   budget month, one pot, a budget_dek row by opening the budget once, a
//   subscription row exists automatically from the signup trigger). That gives the
//   probe real victim rows to try to reach.
//
//   The anon/publishable apikey is the one the client already ships
//   (database/config/supabaseConfig.js -> PUBLISHABLE_API_KEY). It is public by
//   design; RLS is the boundary, so pass it as SUPABASE_ANON_KEY.
//
// ----------------------------------------------------------------------------
// RUN
// ----------------------------------------------------------------------------
//   SUPABASE_URL="https://<ref>.supabase.co" \
//   SUPABASE_ANON_KEY="sb_publishable_..." \
//   ATTACKER_JWT="<attacker access_token>" \
//   VICTIM_USER_ID="<victim user uuid>" \
//   node auth_db/security/dast/rls_abuse_probe.mjs
//
//   Optional extra precision (recommended) — give the probe concrete victim row
//   ids so the cross-user writes/deletes target REAL rows (otherwise the probe
//   discovers what it can and notes when it had nothing to aim at):
//     VICTIM_MESSAGE_ID, VICTIM_CONVERSATION_ID, VICTIM_USER_MONTH_ID,
//     VICTIM_POT_ID, VICTIM_SHARE_ID, ATTACKER_USER_ID
//
// EXIT CODE: non-zero if ANY check returned FAIL (so it can gate CI).
// ============================================================================

const SUPABASE_URL   = req('SUPABASE_URL');
const ANON_KEY       = req('SUPABASE_ANON_KEY');
const ATTACKER_JWT   = req('ATTACKER_JWT');
const VICTIM_USER_ID = req('VICTIM_USER_ID');

// Optional, sharpen the probe if provided:
const ATTACKER_USER_ID       = process.env.ATTACKER_USER_ID || null;
const VICTIM_MESSAGE_ID      = process.env.VICTIM_MESSAGE_ID || null;
const VICTIM_CONVERSATION_ID = process.env.VICTIM_CONVERSATION_ID || null;
const VICTIM_USER_MONTH_ID   = process.env.VICTIM_USER_MONTH_ID || null;
const VICTIM_POT_ID          = process.env.VICTIM_POT_ID || null;
const VICTIM_SHARE_ID        = process.env.VICTIM_SHARE_ID || null;

function req(name) {
  const v = process.env[name];
  if (!v) {
    console.error(`\n[setup] missing required env var ${name}. See the header of this file.\n`);
    process.exit(2);
  }
  return v;
}

const REST = `${SUPABASE_URL.replace(/\/$/, '')}/rest/v1`;
const HEADERS = {
  apikey: ANON_KEY,
  Authorization: `Bearer ${ATTACKER_JWT}`,
  'Content-Type': 'application/json',
};

const results = [];
function record(name, status, detail) {
  results.push({ name, status, detail });
  const tag = status === 'PASS' ? '\x1b[32mPASS\x1b[0m'
            : status === 'FAIL' ? '\x1b[31mFAIL\x1b[0m'
            : '\x1b[33mINFO\x1b[0m';
  console.log(`[${tag}] ${name}${detail ? '  — ' + detail : ''}`);
}

// PostgREST GET with a filter. Returns { ok, status, rows }.
async function get(table, query) {
  const url = `${REST}/${table}${query ? '?' + query : ''}`;
  const r = await fetch(url, { method: 'GET', headers: HEADERS });
  let rows = [];
  try { rows = await r.json(); } catch { rows = null; }
  return { ok: r.ok, status: r.status, rows };
}

// PostgREST PATCH (UPDATE) with a filter + body.
async function patch(table, query, body) {
  const url = `${REST}/${table}${query ? '?' + query : ''}`;
  const r = await fetch(url, {
    method: 'PATCH',
    headers: { ...HEADERS, Prefer: 'return=representation' },
    body: JSON.stringify(body),
  });
  let rows = null;
  try { rows = await r.json(); } catch {}
  return { ok: r.ok, status: r.status, rows };
}

// PostgREST DELETE with a filter.
async function del(table, query) {
  const url = `${REST}/${table}${query ? '?' + query : ''}`;
  const r = await fetch(url, {
    method: 'DELETE',
    headers: { ...HEADERS, Prefer: 'return=representation' },
  });
  let rows = null;
  try { rows = await r.json(); } catch {}
  return { ok: r.ok, status: r.status, rows };
}

// PostgREST POST (INSERT).
async function insert(table, body) {
  const r = await fetch(`${REST}/${table}`, {
    method: 'POST',
    headers: { ...HEADERS, Prefer: 'return=representation' },
    body: JSON.stringify(body),
  });
  let rows = null;
  try { rows = await r.json(); } catch {}
  return { ok: r.ok, status: r.status, rows };
}

// RPC: POST /rest/v1/rpc/<fn> with JSON args.
async function rpc(fn, args) {
  const r = await fetch(`${REST}/rpc/${fn}`, {
    method: 'POST',
    headers: HEADERS,
    body: JSON.stringify(args || {}),
  });
  let body = null;
  try { body = await r.json(); } catch {}
  return { ok: r.ok, status: r.status, body };
}

const rowCount = (rows) => (Array.isArray(rows) ? rows.length : 0);

// ============================================================================
// 1. CROSS-USER SELECT — read the victim's rows directly via PostgREST.
//    RLS USING(auth.uid()=user_id) means a victim-filtered SELECT must return 0
//    rows (PostgREST returns 200 + [] when the filter matches rows RLS hides).
//    FAIL = any victim row leaks back.
// ============================================================================
async function crossUserSelects() {
  const cases = [
    // table, filter-column, owner-column meaning, expected-blocked
    ['messages',                  `recipient_id=eq.${VICTIM_USER_ID}`,  'victim inbound messages'],
    ['messages',                  `sender_id=eq.${VICTIM_USER_ID}`,     'victim outbound messages'],
    ['user_months',              `user_id=eq.${VICTIM_USER_ID}`,        'victim budget months'],
    ['pots',                     `user_id=eq.${VICTIM_USER_ID}`,        'victim pots'],
    ['budget_dek',               `user_id=eq.${VICTIM_USER_ID}`,        'victim wrapped budget DEK'],
    ['subscriptions',            `user_id=eq.${VICTIM_USER_ID}`,        'victim subscription row'],
    ['identity_key_backups',     `user_id=eq.${VICTIM_USER_ID}`,        'victim password/recovery key backups'],
    ['conversation_session_keys',`user_id=eq.${VICTIM_USER_ID}`,        'victim session-key backups'],
    ['settings',                 `user_id=eq.${VICTIM_USER_ID}`,        'victim settings'],
    ['notifications',            `user_id=eq.${VICTIM_USER_ID}`,        'victim notifications'],
    ['pairing_requests',         `user_id=eq.${VICTIM_USER_ID}`,        'victim pairing bundles (wrapped identity secret!)'],
    ['payment_history',          `user_id=eq.${VICTIM_USER_ID}`,        'victim payment history'],
    // data_shares is involved-scoped (owner OR recipient): a third party must not read it.
    ['data_shares',              `owner_user_id=eq.${VICTIM_USER_ID}`,  'victim-owned data shares (3rd-party view)'],
    // OPK pool is own-row only since M-2: a peer must NOT be able to enumerate it.
    ['one_time_prekeys',         `user_id=eq.${VICTIM_USER_ID}`,        'victim OPK pool enumeration (M-2 recon oracle)'],
    // service-role-only ledgers: a client must read nothing.
    ['opk_claim_audit',          `target_id=eq.${VICTIM_USER_ID}`,      'who-claimed-victim-OPK ledger'],
  ];
  for (const [table, filter, what] of cases) {
    const { status, rows } = await get(table, `${filter}&select=*`);
    if (status === 404) { record(`SELECT ${table} (${what})`, 'INFO', 'table not on this deploy (404)'); continue; }
    const leaked = rowCount(rows);
    record(
      `SELECT ${table} cross-user (${what})`,
      leaked > 0 ? 'FAIL' : 'PASS',
      leaked > 0 ? `LEAKED ${leaked} victim row(s)` : `blocked (status ${status}, 0 rows)`
    );
  }
}

// ============================================================================
// 2. PUBLIC-BY-DESIGN READS — these SHOULD be readable by any authenticated user
//    (key-exchange material). We assert they return rows for the victim so the
//    probe also flags an over-restriction regression, not just a leak. These are
//    INFO (expected-readable), not FAIL.
// ============================================================================
async function publicReads() {
  for (const [table, what] of [
    ['identity_keys',      'victim X25519 identity public key (TOFU material)'],
    ['prekeys',            'victim signed-prekey bundle (X3DH)'],
    ['public_key_history', 'victim historical public keys'],
  ]) {
    const { status, rows } = await get(table, `user_id=eq.${VICTIM_USER_ID}&select=user_id`);
    record(`SELECT ${table} (${what})`, 'INFO',
      `status ${status}, ${rowCount(rows)} row(s) — expected READABLE (public key material)`);
  }
}

// ============================================================================
// 3. CROSS-USER UPDATE / DELETE — try to mutate the victim's rows.
//    RLS + column grants must block. PostgREST returns 200 + [] when the row is
//    invisible (nothing matched), 403/401 on a hard deny, or 200 + [row] if it
//    actually wrote (FAIL).
// ============================================================================
async function crossUserWrites() {
  // 3a. Mark a victim's message read (only the recipient may; attacker is neither).
  if (VICTIM_MESSAGE_ID) {
    const { status, rows } = await patch('messages', `id=eq.${VICTIM_MESSAGE_ID}`, { read: true });
    record('UPDATE victim message.read', writeBlocked(status, rows) ? 'PASS' : 'FAIL',
      detailFor(status, rows));
  } else {
    record('UPDATE victim message.read', 'INFO', 'set VICTIM_MESSAGE_ID to test concretely');
  }

  // 3b. Delete a victim's message (only the sender may delete; attacker is not).
  if (VICTIM_MESSAGE_ID) {
    const { status, rows } = await del('messages', `id=eq.${VICTIM_MESSAGE_ID}`);
    record('DELETE victim message', writeBlocked(status, rows) ? 'PASS' : 'FAIL', detailFor(status, rows));
  }

  // 3c. Overwrite a victim budget month (user_months_update_own + WITH CHECK).
  if (VICTIM_USER_MONTH_ID) {
    const { status, rows } = await patch('user_months', `id=eq.${VICTIM_USER_MONTH_ID}`,
      { month_name: 'PWNED_BY_PROBE' });
    record('UPDATE victim user_months', writeBlocked(status, rows) ? 'PASS' : 'FAIL', detailFor(status, rows));
  } else {
    record('UPDATE victim user_months', 'INFO', 'set VICTIM_USER_MONTH_ID to test concretely');
  }

  // 3d. Steal a victim budget month by reassigning user_id to the attacker
  //     (RLS-02: the WITH CHECK must stop user_id reassignment).
  if (VICTIM_USER_MONTH_ID && ATTACKER_USER_ID) {
    const { status, rows } = await patch('user_months', `id=eq.${VICTIM_USER_MONTH_ID}`,
      { user_id: ATTACKER_USER_ID });
    record('UPDATE victim user_months -> steal (user_id reassign)',
      writeBlocked(status, rows) ? 'PASS' : 'FAIL', detailFor(status, rows));
  }

  // 3e. Overwrite a victim pot.
  if (VICTIM_POT_ID) {
    const { status, rows } = await patch('pots', `id=eq.${VICTIM_POT_ID}`, { name: 'PWNED_BY_PROBE' });
    record('UPDATE victim pot', writeBlocked(status, rows) ? 'PASS' : 'FAIL', detailFor(status, rows));
  } else {
    record('UPDATE victim pot', 'INFO', 'set VICTIM_POT_ID to test concretely');
  }

  // 3f. Overwrite the victim's wrapped budget DEK (catastrophic if writable).
  const { status: dekS, rows: dekR } = await patch('budget_dek', `user_id=eq.${VICTIM_USER_ID}`,
    { wrapped_dek: 'AAAA', wrap_nonce: 'AAAA' });
  record('UPDATE victim budget_dek (wrapped key)',
    writeBlocked(dekS, dekR) ? 'PASS' : 'FAIL', detailFor(dekS, dekR));
}

// ============================================================================
// 4. SELF-GRANT PREMIUM — the entitlement lockdown.
//    The REVOKE means authenticated cannot INSERT/UPDATE subscriptions directly.
//    Try both a direct PATCH of the attacker's own row to 'active'/Premium and a
//    direct INSERT. Either succeeding = FAIL (client-writable entitlement).
// ============================================================================
async function selfGrantPremium() {
  const tgt = ATTACKER_USER_ID ? `user_id=eq.${ATTACKER_USER_ID}` : `status=eq.trial`;
  const upd = await patch('subscriptions', tgt, { status: 'active' });
  // A privilege-revoked column write returns 401/403/4xx, or 200 + [] (nothing
  // written because UPDATE is revoked). FAIL only if it actually returns a
  // written row with status active.
  const wrote = Array.isArray(upd.rows) && upd.rows.some(r => r && r.status === 'active');
  record('UPDATE own subscription -> active (self-grant)',
    (!wrote) ? 'PASS' : 'FAIL',
    wrote ? 'subscription set active by direct client write!' : detailFor(upd.status, upd.rows));

  // Direct INSERT of a Premium/active row for self.
  const ins = await insert('subscriptions',
    { user_id: ATTACKER_USER_ID || VICTIM_USER_ID, plan_id: 2, status: 'active' });
  const inserted = Array.isArray(ins.rows) && ins.rows.length > 0 && ins.rows[0] && ins.rows[0].id;
  record('INSERT subscriptions (self-grant premium)',
    (!inserted) ? 'PASS' : 'FAIL',
    inserted ? 'client INSERT into subscriptions succeeded!' : detailFor(ins.status, ins.rows));
}

// ============================================================================
// 5. data_shares PENDING-WINDOW ESCALATION (SEC-C1).
//    As a RECIPIENT accepting a pending share, try to ALSO flip can_edit /
//    share_all_data in the same PATCH. The column GRANT(status) + WITH CHECK must
//    reject the privileged columns (42501 / blocked). FAIL = the grant flags move.
//    Needs a pending share TO the attacker; set VICTIM_SHARE_ID to that share id.
// ============================================================================
async function pendingWindowEscalation() {
  if (!VICTIM_SHARE_ID) {
    record('data_shares recipient self-escalation (can_edit/share_all_data)', 'INFO',
      'set VICTIM_SHARE_ID to a pending share addressed to the attacker to test');
    return;
  }
  // Attempt to accept AND escalate in one PATCH.
  const escal = await patch('data_shares', `id=eq.${VICTIM_SHARE_ID}`,
    { status: 'accepted', can_edit: true, share_all_data: true });
  const escalated = Array.isArray(escal.rows) && escal.rows.some(r => r && (r.can_edit === true || r.share_all_data === true));
  record('data_shares recipient self-escalation (accept + flip grants)',
    (!escalated) ? 'PASS' : 'FAIL',
    escalated ? 'recipient escalated can_edit/share_all_data!' : detailFor(escal.status, escal.rows));

  // Also try escalation alone (no status change).
  const flip = await patch('data_shares', `id=eq.${VICTIM_SHARE_ID}`, { can_edit: true });
  const flipped = Array.isArray(flip.rows) && flip.rows.some(r => r && r.can_edit === true);
  record('data_shares recipient flips can_edit only',
    (!flipped) ? 'PASS' : 'FAIL',
    flipped ? 'recipient set can_edit=true via direct PATCH!' : detailFor(flip.status, flip.rows));
}

// ============================================================================
// 6. SECURITY DEFINER RPC abuse across the user boundary.
// ============================================================================
async function rpcAbuse() {
  // 6a. claim_one_time_prekey(target) — legitimate for any peer (it's how X3DH
  //     bootstraps). It should SUCCEED but be RATE-LIMITED. We hammer it past the
  //     per-(caller,target) cap (OPK_MAX_PER_PAIR = 10 / hour) and assert the
  //     server starts returning {success:false,error:'rate limited'}. FAIL = no
  //     cap kicks in after >10 successful claims (a forward-secrecy drain).
  let okClaims = 0, rateLimited = false, lastErr = null;
  for (let i = 0; i < 14; i++) {
    const { body } = await rpc('claim_one_time_prekey', { target_user_id: VICTIM_USER_ID });
    if (body && body.success === true) okClaims++;
    else if (body && /rate limited/i.test(body.error || '')) { rateLimited = true; break; }
    else lastErr = body && body.error;
  }
  // If the victim has no prekey bundle the RPC returns success:false 'no prekey
  // bundle for target' — that's not a drain, it's just unreachable; mark INFO.
  if (okClaims === 0 && !rateLimited) {
    record('RPC claim_one_time_prekey drain', 'INFO',
      `no successful claims (${lastErr || 'victim likely has no published prekeys'}) — seed victim prekeys to test the cap`);
  } else {
    record('RPC claim_one_time_prekey rate-limit (OPK drain)',
      rateLimited ? 'PASS' : 'FAIL',
      rateLimited ? `cap engaged after ${okClaims} claim(s)` : `made ${okClaims} claims with NO rate limit`);
  }

  // 6b. create_notification — must reject a target the caller has NO relationship
  //     with (M-5). Notify a random/victim UUID the attacker is not connected to.
  const note = await rpc('create_notification', {
    p_user_id: VICTIM_USER_ID, p_type: 'friend_request', p_message: 'probe'
  });
  const injected = note.body && note.body.success === true;
  // If attacker IS connected to victim this would legitimately succeed; only a
  // definitive cross-user inject (no relationship) is a FAIL. We report the raw
  // result and let the operator judge based on whether the two are unrelated.
  record('RPC create_notification cross-user inject (M-5)',
    injected ? 'FAIL' : 'PASS',
    injected ? 'notification injected into victim feed (FAIL only if NO relationship exists)'
             : `rejected: ${note.body && note.body.error}`);

  // 6c. create_notification — forge a server-only financial type.
  const forge = await rpc('create_notification', {
    p_user_id: ATTACKER_USER_ID || VICTIM_USER_ID, p_type: 'payment_received', p_message: 'probe'
  });
  const forged = forge.body && forge.body.success === true;
  record('RPC create_notification forge payment_received',
    forged ? 'FAIL' : 'PASS',
    forged ? 'client forged a financial notification type!' : `rejected: ${forge.body && forge.body.error}`);

  // 6d. update_share_grants on a share the attacker does NOT own — must be
  //     rejected ('not the share owner'). Uses VICTIM_SHARE_ID (a victim-owned
  //     share) if provided.
  if (VICTIM_SHARE_ID) {
    const usg = await rpc('update_share_grants', {
      p_share_id: Number(VICTIM_SHARE_ID), p_can_edit: true, p_share_all_data: true
    });
    const owned = usg.body && usg.body.success === true;
    record('RPC update_share_grants on non-owned share',
      owned ? 'FAIL' : 'PASS',
      owned ? 'mutated grants on a share the caller does not own!' : `rejected: ${usg.body && usg.body.error}`);
  } else {
    record('RPC update_share_grants on non-owned share', 'INFO',
      'set VICTIM_SHARE_ID to a VICTIM-OWNED share id to test');
  }

  // 6e. start_trial replay — calling it when already past-trial must NOT re-grant.
  const st = await rpc('start_trial', {});
  record('RPC start_trial replay', 'INFO',
    `result: ${st.body && (st.body.error || (st.body.subscription ? 'returned a subscription' : JSON.stringify(st.body)))} — FAIL only if it re-grants a consumed trial`);

  // 6f. resolve_user_id_by_email — must be service_role-only (REVOKEd from
  //     authenticated). A direct client call must be denied.
  const res = await rpc('resolve_user_id_by_email', { p_caller_id: VICTIM_USER_ID, p_email: 'probe@example.com' });
  const allowed = res.body && (res.body.status === 'ok' || res.body.status === 'not_found' || res.body.status === 'rate_limited');
  record('RPC resolve_user_id_by_email direct client call',
    allowed ? 'FAIL' : 'PASS',
    allowed ? 'service-role-only resolver callable by authenticated!' : `denied (status ${res.status})`);
}

// ---- helpers for write-blocked interpretation -----------------------------
// A cross-user write is "blocked" when the server did NOT write the targeted row:
//   - 401/403 hard deny, OR
//   - 2xx but returned an EMPTY representation array (RLS hid the row -> 0 affected).
// It is a FAIL when 2xx returns a non-empty representation (a row was written).
function writeBlocked(status, rows) {
  if (status === 401 || status === 403 || status === 404) return true;
  if (status >= 400) return true;
  if (Array.isArray(rows)) return rows.length === 0;       // 0 rows affected = blocked by RLS
  return false;                                            // ambiguous -> treat as not-blocked (FAIL-safe)
}
function detailFor(status, rows) {
  const n = Array.isArray(rows) ? rows.length : (rows && rows.message ? `err:${rows.message}` : '?');
  return `status ${status}, affected/returned ${n}`;
}

// ============================================================================
async function main() {
  console.log(`\n=== RLS abuse probe vs ${REST} ===`);
  console.log(`attacker JWT (truncated): ${ATTACKER_JWT.slice(0, 12)}…   victim: ${VICTIM_USER_ID}\n`);

  await crossUserSelects();
  console.log('');
  await publicReads();
  console.log('');
  await crossUserWrites();
  console.log('');
  await selfGrantPremium();
  console.log('');
  await pendingWindowEscalation();
  console.log('');
  await rpcAbuse();

  const fails = results.filter(r => r.status === 'FAIL');
  console.log(`\n=== summary: ${results.filter(r=>r.status==='PASS').length} PASS, ` +
              `${fails.length} FAIL, ${results.filter(r=>r.status==='INFO').length} INFO ===`);
  if (fails.length) {
    console.log('\nFAILing checks (server ALLOWED a cross-user / privilege action):');
    for (const f of fails) console.log(`  - ${f.name}  (${f.detail})`);
    process.exit(1);
  }
  console.log('\nNo FAILs: RLS held against every probed cross-user attempt. ' +
              '(Absence of a FAIL is evidence, not proof — extend the probe and pair with ZAP/sqlmap.)');
}

main().catch(err => {
  console.error('\n[probe error]', err && err.stack ? err.stack : err);
  process.exit(2);
});
