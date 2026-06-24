import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.39.7'

/**
 * delete-account Edge Function (Secure Messenger)
 *
 * Permanently deletes the CALLER's account and all of their data.
 *
 * Runs with the SERVICE-ROLE key so it can use the Admin API and delete Storage
 * objects across RLS.
 *
 * SECURITY INVARIANTS:
 *   (a) Identity is EXCLUSIVELY `user.id` resolved from auth.getUser(jwt). The
 *       request body is NEVER trusted for identity — no user id is ever read
 *       from the body or query string.
 *   (b) The service-role key is never returned or logged.
 *   (c) Unauthenticated / invalid-token requests get 401 and perform NO deletion.
 *   (d) Storage cleanup happens BEFORE admin.deleteUser so participant resolution
 *       is still possible (the conversation rows are gone after deletion).
 *
 * Deletion contract:
 *   1. Collect the user's conversation ids.
 *   2. Remove Storage attachment objects from the `message-attachments` bucket
 *      (Storage objects are NOT covered by the FK cascade).
 *   3. admin.deleteUser(user.id) — cascades every ON DELETE CASCADE FK row in
 *      the public schema (friends, blocked_users, identity_keys,
 *      public_key_history, paired_devices, device_keys, key_rotation_locks,
 *      conversations, messages, message_attachments, conversation_session_keys,
 *      identity_key_backups).
 *   4. Return 200 with a summary.
 */

const BUCKET_NAME = 'message-attachments'

// SM-20: restrict CORS to the deployed app origin via ALLOWED_ORIGIN; fall back
// to the known app origin (NEVER '*') so an unauthorized origin is not granted access.
const ALLOWED_ORIGIN = Deno.env.get('ALLOWED_ORIGIN') ?? 'https://nicholasantoniadesengineer.github.io'

const corsHeaders = {
  'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
}

function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  })
}

serve(async (req) => {
  // CORS preflight.
  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders })
  }

  // Only POST is accepted.
  if (req.method !== 'POST') {
    return jsonResponse({ error: 'Method not allowed' }, 405)
  }

  const supabaseUrl = Deno.env.get('SUPABASE_URL')
  const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')

  if (!supabaseUrl || !serviceRoleKey) {
    // Do not leak which secret is missing.
    return jsonResponse({ error: 'Server configuration error' }, 500)
  }

  // Service-role client (Admin API + Storage across RLS).
  const serviceClient = createClient(supabaseUrl, serviceRoleKey, {
    auth: { persistSession: false },
  })

  // --- Auth: derive identity from the verified token ONLY ---
  const authHeader = req.headers.get('Authorization') ?? ''
  const jwt = authHeader.startsWith('Bearer ')
    ? authHeader.slice('Bearer '.length).trim()
    : ''

  if (!jwt) {
    return jsonResponse({ error: 'Missing authorization header' }, 401)
  }

  const { data: { user }, error: getUserError } = await serviceClient.auth.getUser(jwt)
  if (getUserError || !user) {
    return jsonResponse({ error: 'Invalid or expired token' }, 401)
  }

  // The ONLY identity we ever act on. Never read from the body/query.
  const userId = user.id

  const warnings: string[] = []
  let storageObjectsRemoved = 0

  // --- 1. Collect the user's conversation ids ---
  const conversationIds: string[] = []
  try {
    const { data: conversations, error: convError } = await serviceClient
      .from('conversations')
      .select('id')
      .or(`user1_id.eq.${userId},user2_id.eq.${userId}`)

    if (convError) {
      warnings.push(`Failed to list conversations: ${convError.message}`)
    } else if (conversations) {
      for (const row of conversations) {
        if (row && row.id !== undefined && row.id !== null) {
          conversationIds.push(String(row.id))
        }
      }
    }
  } catch (e) {
    warnings.push(`Exception listing conversations: ${(e as Error).message}`)
  }

  // --- 2. Remove Storage attachment objects (NOT cascaded) ---
  // Object path scheme: `<conversationId>/<timestamp>-<randomId>`.
  for (const convId of conversationIds) {
    try {
      let offset = 0
      const pageSize = 1000
      // Paginate in case a folder exceeds the list limit.
      // deno-lint-ignore no-constant-condition
      while (true) {
        const { data: objects, error: listError } = await serviceClient.storage
          .from(BUCKET_NAME)
          .list(`${convId}`, { limit: pageSize, offset })

        if (listError) {
          warnings.push(`Failed to list storage for conversation ${convId}: ${listError.message}`)
          break
        }
        if (!objects || objects.length === 0) {
          break
        }

        const keys = objects.map((o) => `${convId}/${o.name}`)
        const { error: removeError } = await serviceClient.storage
          .from(BUCKET_NAME)
          .remove(keys)

        if (removeError) {
          warnings.push(`Failed to remove storage for conversation ${convId}: ${removeError.message}`)
        } else {
          storageObjectsRemoved += keys.length
        }

        if (objects.length < pageSize) {
          break
        }
        offset += pageSize
      }
    } catch (e) {
      // Do not abort on a single folder failure — the cascade still removes rows.
      warnings.push(`Exception removing storage for conversation ${convId}: ${(e as Error).message}`)
    }
  }

  // Cross-check: remove any objects whose owning conversation row was already
  // gone, by their recorded storage_path. Removal is idempotent.
  try {
    const { data: attachments, error: attachError } = await serviceClient
      .from('message_attachments')
      .select('storage_path')
      .eq('uploader_id', userId)

    if (attachError) {
      warnings.push(`Failed to list message_attachments: ${attachError.message}`)
    } else if (attachments && attachments.length > 0) {
      const paths = attachments
        .map((a) => a.storage_path)
        .filter((p): p is string => typeof p === 'string' && p.length > 0)
      if (paths.length > 0) {
        const { error: removeError } = await serviceClient.storage
          .from(BUCKET_NAME)
          .remove(paths)
        if (removeError) {
          warnings.push(`Failed to remove attachment storage paths: ${removeError.message}`)
        } else {
          storageObjectsRemoved += paths.length
        }
      }
    }
  } catch (e) {
    warnings.push(`Exception cross-checking message_attachments: ${(e as Error).message}`)
  }

  // --- 3. Delete the auth user (cascades all FK rows) ---
  const { error: delErr } = await serviceClient.auth.admin.deleteUser(userId)
  if (delErr) {
    // admin.deleteUser is idempotent against an already-deleted id; treat a
    // "user not found" style error as success so retries succeed.
    const msg = (delErr.message || '').toLowerCase()
    const idempotent = msg.includes('not found') || msg.includes('does not exist')
    if (!idempotent) {
      console.error('[delete-account] deleteUser failed:', delErr.message)
      return jsonResponse({ error: 'Account deletion failed' }, 500)
    }
    warnings.push('User already deleted (idempotent).')
  }

  // --- 4. Success --- (don't reflect internal detail/ids to the client)
  if (warnings.length > 0) {
    console.warn('[delete-account] non-fatal warnings:', warnings)
  }
  return jsonResponse({
    success: true,
    storageObjectsRemoved,
    warningCount: warnings.length,
  }, 200)
})
