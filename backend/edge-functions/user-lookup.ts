import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.39.7'

// SM-20: Restrict CORS to the deployed app origin instead of a wildcard '*'.
// Configure via the ALLOWED_ORIGIN env var; falls back to a non-wildcard
// placeholder so an unauthorized cross-origin caller is never granted access.
const ALLOWED_ORIGIN = Deno.env.get('ALLOWED_ORIGIN') ?? 'https://your-app-domain.example'

const corsHeaders = {
  'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

/**
 * User Lookup Edge Function
 *
 * Handles all user lookup operations using admin privileges.
 *
 * Operations:
 * - findByEmail: Look up user ID by email address
 * - getEmailById: Look up email by user ID
 */
serve(async (req) => {
  // Handle CORS preflight requests
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    const supabaseUrl = Deno.env.get('SUPABASE_URL')!
    const supabaseServiceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
    const supabaseAnonKey = Deno.env.get('SUPABASE_ANON_KEY')!

    // SM-20: Authorize the caller BEFORE doing any privileged work.
    // Require a Bearer JWT and verify it with the project's anon client
    // (auth.getUser). Reject (401) if the header is missing/malformed or the
    // token does not resolve to a real authenticated user.
    const authHeader = req.headers.get('Authorization') ?? ''
    const token = authHeader.startsWith('Bearer ')
      ? authHeader.slice('Bearer '.length).trim()
      : ''

    if (!token) {
      return new Response(
        JSON.stringify({ error: 'Unauthorized: missing bearer token' }),
        {
          status: 401,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        }
      )
    }

    // Verify the JWT against Supabase Auth using the anon (non-privileged) client.
    const supabaseAuthClient = createClient(supabaseUrl, supabaseAnonKey, {
      auth: {
        autoRefreshToken: false,
        persistSession: false
      }
    })

    const { data: authData, error: authError } = await supabaseAuthClient.auth.getUser(token)

    // Reject if the token is invalid/expired or does not map to a real user
    // (e.g. the bare anon key, which has no associated user).
    if (authError || !authData?.user) {
      return new Response(
        JSON.stringify({ error: 'Unauthorized: invalid or expired token' }),
        {
          status: 401,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        }
      )
    }

    // Caller is authenticated — now create the service-role client (bypasses RLS)
    // used to perform the actual admin lookups.
    const supabaseAdmin = createClient(supabaseUrl, supabaseServiceRoleKey, {
      auth: {
        autoRefreshToken: false,
        persistSession: false
      }
    })

    // Parse request body
    const body = await req.json()
    const { action, email, userId } = body

    // Validate action parameter
    if (!action) {
      return new Response(
        JSON.stringify({ error: 'Action parameter is required' }),
        {
          status: 400,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        }
      )
    }

    // Route to appropriate handler
    switch (action) {
      case 'findByEmail':
        // W3-3: pass the JWT-verified caller id so the resolver can rate-limit
        // per-caller. The lookup itself is a targeted, paginated-safe DB query.
        return await handleFindByEmail(supabaseAdmin, email, authData.user.id)

      case 'getEmailById':
        // L-1: pass the JWT-verified caller id so the resolver can rate-limit
        // per-caller (shared budget with findByEmail) and so the response can be
        // made a uniform 200 { email | null } instead of a user-id existence oracle.
        return await handleGetEmailById(supabaseAdmin, userId, authData.user.id)

      default:
        return new Response(
          JSON.stringify({ error: `Unknown action: ${action}` }),
          {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          }
        )
    }

  } catch (error) {
    console.error('Exception in user-lookup:', error)
    return new Response(
      JSON.stringify({ error: error.message || 'An unexpected error occurred' }),
      {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      }
    )
  }
})

/**
 * Find user ID by email address (W3-3 hardened).
 *
 * Old behaviour was an unthrottled account-existence oracle that also paged the
 * WHOLE user table (auth.admin.listUsers() returns only the first ~50 users, so
 * it silently missed users past page 1). This version:
 *   - resolves via the SECURITY DEFINER `resolve_user_id_by_email` RPC, a single
 *     INDEXED query against auth.users (paginated-safe at any scale, no full read);
 *   - rate-limits per caller inside that RPC (the caller id from the verified JWT
 *     is passed in; the RPC counts hits AND misses);
 *   - returns a UNIFORM 200 shape `{ userId: <id|null> }` for both found and
 *     not-found, so the response status no longer doubles as a membership oracle.
 *     A genuine caller still gets the userId it needs to start a conversation/share.
 */
async function handleFindByEmail(supabaseAdmin: any, email: string, callerId: string) {
  if (!email) {
    return new Response(
      JSON.stringify({ error: 'Email is required' }),
      {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      }
    )
  }

  // Targeted, rate-limited resolution. The RPC is granted to service_role only.
  const { data, error } = await supabaseAdmin.rpc('resolve_user_id_by_email', {
    p_caller_id: callerId,
    p_email: email,
  })

  if (error) {
    console.error('Error resolving user by email:', error)
    return new Response(
      JSON.stringify({ error: 'Failed to search for user' }),
      {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      }
    )
  }

  // Rate limit exceeded -> 429 (do NOT leak existence either way).
  if (data?.status === 'rate_limited') {
    return new Response(
      JSON.stringify({ error: 'Too many lookups, please try again later' }),
      {
        status: 429,
        headers: {
          ...corsHeaders,
          'Content-Type': 'application/json',
          ...(data.retry_after_seconds ? { 'Retry-After': String(data.retry_after_seconds) } : {}),
        }
      }
    )
  }

  if (data?.status === 'error') {
    console.error('resolve_user_id_by_email error:', data.error)
    return new Response(
      JSON.stringify({ error: 'Failed to search for user' }),
      {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      }
    )
  }

  // Uniform 200 for both found and not-found: { userId: <id|null> }. This blunts
  // the 200-vs-404 existence oracle; the legitimate caller reads userId when set.
  const resolvedId = data?.status === 'ok' ? data.user_id : null
  return new Response(
    JSON.stringify({ userId: resolvedId }),
    {
      status: 200,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    }
  )
}

/**
 * Get email by user ID (L-1 hardened — mirrors W3-3's findByEmail).
 *
 * Old behaviour was an unthrottled reverse-lookup that returned 404-vs-200 keyed
 * on the user id (a user-id existence oracle) via a raw auth.admin.getUserById().
 * This version:
 *   - resolves via the SECURITY DEFINER `resolve_email_by_user_id` RPC, a single
 *     INDEXED lookup against auth.users by primary key;
 *   - rate-limits per caller inside that RPC (the caller id from the verified JWT
 *     is passed in; the RPC counts hits AND misses; SHARED budget with
 *     resolve_user_id_by_email so a caller can't dodge the cap by alternating);
 *   - returns a UNIFORM 200 shape `{ email: <addr|null> }` for both found and
 *     not-found, so the response status no longer doubles as an existence oracle.
 *     A genuine caller still gets the email it needs; the client treats a null
 *     email as a clean "not found".
 */
async function handleGetEmailById(supabaseAdmin: any, userId: string, callerId: string) {
  if (!userId) {
    return new Response(
      JSON.stringify({ error: 'User ID is required' }),
      {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      }
    )
  }

  // Targeted, rate-limited resolution. The RPC is granted to service_role only.
  const { data, error } = await supabaseAdmin.rpc('resolve_email_by_user_id', {
    p_caller_id: callerId,
    p_user_id: userId,
  })

  if (error) {
    console.error('Error resolving email by user id:', error)
    return new Response(
      JSON.stringify({ error: 'Failed to get user' }),
      {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      }
    )
  }

  // Rate limit exceeded -> 429 (do NOT leak existence either way).
  if (data?.status === 'rate_limited') {
    return new Response(
      JSON.stringify({ error: 'Too many lookups, please try again later' }),
      {
        status: 429,
        headers: {
          ...corsHeaders,
          'Content-Type': 'application/json',
          ...(data.retry_after_seconds ? { 'Retry-After': String(data.retry_after_seconds) } : {}),
        }
      }
    )
  }

  if (data?.status === 'error') {
    console.error('resolve_email_by_user_id error:', data.error)
    return new Response(
      JSON.stringify({ error: 'Failed to get user' }),
      {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      }
    )
  }

  // Uniform 200 for both found and not-found: { email: <addr|null> }. This blunts
  // the 200-vs-404 existence oracle; the legitimate caller reads email when set.
  const resolvedEmail = data?.status === 'ok' ? data.email : null
  return new Response(
    JSON.stringify({ email: resolvedEmail }),
    {
      status: 200,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    }
  )
}
