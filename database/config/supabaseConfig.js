/**
 * Supabase Configuration
 * Centralized configuration for the Supabase client.
 *
 * ============================================================================
 * SHARED BACKEND — Secure Messenger is a SECOND front-end on the SAME Supabase
 * project as the companion Money Tracker app.
 * ============================================================================
 * Same project URL + publishable/anon key => same Auth (users log in with the
 * SAME credentials) and the same Postgres database, Storage, Realtime and edge
 * functions. No separate Supabase setup is required: the messaging/encryption
 * tables, the subscription tables + trial trigger, the `message-attachments`
 * storage bucket, and the `user-lookup` edge function already exist there.
 *
 * The SQL files in database/setup/ are REFERENCE schemas for a hypothetical
 * standalone deployment; they are NOT needed for this shared-backend setup.
 *
 * The anon/publishable key is safe to ship client-side — row-level security
 * (RLS) is what actually protects the data.
 *
 * NOTE: Global logging configuration lives in shared/config/loggingConfig.js;
 * load loggingConfig.js BEFORE this file to control console logging.
 */

const SupabaseConfig = {
    // Shared backend (same project as Money Tracker) — same users, same data.
    PROJECT_URL: 'https://ofutzrxfbrgtbkyafndv.supabase.co',
    PUBLISHABLE_API_KEY: 'sb_publishable_yUPqP6PRjtgphcvS0--vgw_Zy3S_Urd',
    _clientInstance: null,
    
    /**
     * Get Supabase client instance (reuses existing instance if available)
     * @returns {Object} Supabase client
     */
    getClient() {
        console.log('[SupabaseConfig] getClient() called');
        
        // Return existing client if available
        if (this._clientInstance) {
            console.log('[SupabaseConfig] Reusing existing Supabase client instance');
            return this._clientInstance;
        }
        
        if (!window.supabase) {
            console.error('[SupabaseConfig] Supabase client library not loaded');
            throw new Error('Supabase client library not loaded. Please include the Supabase script in your HTML.');
        }
        
        console.log('[SupabaseConfig] Creating new Supabase client with URL:', this.PROJECT_URL);
        this._clientInstance = window.supabase.createClient(this.PROJECT_URL, this.PUBLISHABLE_API_KEY);
        console.log('[SupabaseConfig] Supabase client created successfully');
        return this._clientInstance;
    },
    
    /**
     * Wait for Supabase library to load
     * @param {number} maxWaitTime - Maximum time to wait in milliseconds
     * @returns {Promise<void>}
     */
    async waitForLibrary(maxWaitTime = 10000) {
        const startTime = Date.now();
        while (!window.supabase && (Date.now() - startTime) < maxWaitTime) {
            await new Promise(resolve => setTimeout(resolve, 100));
        }
        if (!window.supabase) {
            throw new Error('Supabase library failed to load within timeout period');
        }
    },
    
    /**
     * Initialize Supabase client
     * @returns {Promise<Object>} Supabase client instance
     */
    async initialize() {
        console.log('[SupabaseConfig] initialize() called');
        if (typeof window === 'undefined') {
            throw new Error('Supabase config can only be used in browser environment');
        }
        
        if (!window.supabase) {
            console.log('[SupabaseConfig] Waiting for Supabase library to load...');
            await this.waitForLibrary();
            console.log('[SupabaseConfig] Supabase library loaded');
        }
        
        return this.getClient();
    }
};

if (typeof window !== 'undefined') {
    window.SupabaseConfig = SupabaseConfig;
}
