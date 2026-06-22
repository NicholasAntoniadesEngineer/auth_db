/**
 * Database Service
 * Main service layer for all database operations using Supabase
 * Replaces localStorage and FileService
 * 
 * ARCHITECTURE:
 * - All database operations go through a centralized query interface
 * - Currently uses direct fetch (native fetch API) due to Supabase JS client hanging
 * - To switch implementations, only modify the query methods below
 * - This ensures reliable, always-fresh data from Supabase
 * 
 * VERSION: 2.0.0 - Enhanced logging for debugging (2025-12-24)
 */

const DatabaseService = {
    VERSION: '2.0.0-enhanced-logging',
    client: null,
    monthsCache: null,
    cacheTimestamp: null,
    CACHE_DURATION: 24 * 60 * 60 * 1000, // 24 hours in milliseconds
    CACHE_STORAGE_KEY: 'money_tracker_months_cache',
    CACHE_TIMESTAMP_KEY: 'money_tracker_cache_timestamp',
    EXAMPLE_YEAR: 2045, // Example data year - protected from deletion
    settingsCache: null,
    settingsCacheUserId: null,
    settingsCachePromise: null,
    
    /**
     * ============================================================================
     * CENTRALIZED DATABASE QUERY INTERFACE
     * ============================================================================
     * All database operations go through these methods.
     * To change how we interact with Supabase, modify ONLY these methods.
     * ============================================================================
     */
    
    /**
     * Get auth service (requires config)
     * @returns {Object} Auth service
     * @throws {Error} If DatabaseConfigHelper is not available or auth service is not configured
     */
    _getAuthService() {
        // Try config system first
        if (typeof DatabaseConfigHelper !== 'undefined') {
            try {
                return DatabaseConfigHelper.getAuthService(this);
            } catch (error) {
                // Fall back to window if config not available
                console.warn('[DatabaseService] Config not available, falling back to window.AuthService:', error.message);
            }
        }
        
        // Fallback to window for backward compatibility
        if (!window.AuthService) {
            throw new Error('AuthService not available. Ensure DatabaseModule.initialize() has been called or window.AuthService is available.');
        }
        return window.AuthService;
    },
    
    /**
     * Get table name from config
     * @param {string} tableKey - Table key (e.g., 'userMonths', 'settings')
     * @returns {string} Table name
     */
    _getTableName(tableKey) {
        // Try config system first
        if (typeof DatabaseConfigHelper !== 'undefined') {
            try {
                return DatabaseConfigHelper.getTableName(this, tableKey);
            } catch (error) {
                // Fall back to defaults if config not available
                console.warn('[DatabaseService] Config not available, using default table name for', tableKey, ':', error.message);
            }
        }
        
        // Fallback to default table names for backward compatibility
        const defaultTables = {
            userMonths: 'user_months',
            exampleMonths: 'example_months',
            settings: 'settings',
            subscriptions: 'subscriptions',
            subscriptionPlans: 'subscription_plans',
            paymentHistory: 'payment_history'
        };
        
        if (defaultTables[tableKey]) {
            return defaultTables[tableKey];
        }
        
        throw new Error(`Table name for '${tableKey}' not found. Ensure DatabaseModule.initialize() has been called or provide a default mapping.`);
    },
    
    /**
     * Get the current authenticated user ID
     * Returns user ID from current session without excessive validation
     * Session validation is now handled by periodic checks in AuthService
     * @returns {Promise<string|null>} User ID or null if not authenticated
     * @throws {Error} If AuthService is not available
     */
    async _getCurrentUserId() {
        const authService = this._getAuthService();

        // Trust current state - don't validate on every call (huge performance improvement)
        // AuthService validates periodically (every 5 minutes) and on auth state changes
        // This prevents hundreds of unnecessary validation calls per page
        if (!authService.isAuthenticated()) {
            console.warn('[DatabaseService] User not authenticated');
            return null;
        }

        const currentUser = authService.getCurrentUser();
        if (!currentUser || !currentUser.id) {
            console.warn('[DatabaseService] No current user found');
            return null;
        }

        return currentUser.id;
    },
    
    /**
     * Get count of user's months in the database
     * Used for enforcing tier limits on number of months
     * @param {string} userId - User ID to count months for
     * @returns {Promise<number>} Number of months
     */
    async getUserMonthCount(userId) {
        try {
            console.log('[DatabaseService] getUserMonthCount() for user:', userId?.slice(0, 8));

            if (!this.client) {
                await this.initialize();
            }

            const tableName = this._getTableName('userMonths');
            const result = await this.querySelect(tableName, {
                select: 'id',
                filter: { user_id: userId }
            });

            const count = result.data?.length || 0;
            console.log('[DatabaseService] User month count:', count);
            return count;
        } catch (error) {
            console.error('[DatabaseService] Error counting user months:', error);
            return 0;
        }
    },

    /**
     * Synchronous version of _getCurrentUserId for backward compatibility
     * Note: This does not validate session - use async version when possible
     * @returns {string|null} User ID or null if not authenticated
     * @throws {Error} If AuthService is not available
     */
    _getCurrentUserIdSync() {
        const authService = this._getAuthService();
        
        if (!authService.isAuthenticated()) {
            return null;
        }
        
        const currentUser = authService.getCurrentUser();
        if (!currentUser || !currentUser.id) {
            return null;
        }
        
        return currentUser.id;
    },
    
    /**
     * Get authentication headers for database requests
     * Uses authenticated user token if available, otherwise falls back to API key
     * Note: This is synchronous for performance - session validation happens in _getCurrentUserId()
     * @returns {Object} Headers object with apikey and Authorization
     * @throws {Error} If client is not initialized
     */
    _getAuthHeaders() {
        console.log('[DatabaseService] _getAuthHeaders() called');
        console.log('[DatabaseService] _getAuthHeaders - client state:', {
            hasClient: !!this.client,
            clientType: this.client?.constructor?.name,
            hasSupabaseKey: !!this.client?.supabaseKey,
            supabaseKeyLength: this.client?.supabaseKey?.length,
            clientIsNull: this.client === null,
            clientIsUndefined: this.client === undefined
        });
        
        if (!this.client || !this.client.supabaseKey) {
            const error = new Error('DatabaseService client not initialized - cannot get auth headers');
            console.error('[DatabaseService] ❌ _getAuthHeaders error:', error);
            console.error('[DatabaseService] _getAuthHeaders - client value:', this.client);
            console.error('[DatabaseService] _getAuthHeaders - call stack:', new Error().stack?.split('\n').slice(1, 6).join('\n'));
            throw error;
        }
        
        console.log('[DatabaseService] _getAuthHeaders - client is valid, proceeding');
        let authToken = this.client.supabaseKey;
        
        // Try to get authenticated user token from AuthService
        // Note: We don't validate session here for performance - validation happens in _getCurrentUserId()
        // If session is invalid, _getCurrentUserId() will handle redirect
        try {
            const authService = this._getAuthService();
            if (authService && authService.isAuthenticated()) {
                const accessToken = authService.getAccessToken();
                if (accessToken) {
                    authToken = accessToken;
                }
            }
        } catch (error) {
            // AuthService not available via config, continue with API key
            console.warn('[DatabaseService] Could not get auth service for token:', error.message);
        }
        
        return {
            'apikey': this.client.supabaseKey,
            'Authorization': `Bearer ${authToken}`,
            'Content-Type': 'application/json',
            'Prefer': 'return=representation'
        };
    },
    
    /**
     * Execute a SELECT query
     * @param {string} table - Table name
     * @param {Object} options - Query options
     * @returns {Promise<{data: Array|null, error: Object|null}>}
     */
    async querySelect(table, options = {}) {
        console.log('[DatabaseService] ========== querySelect CALLED ==========');
        console.log('[DatabaseService] querySelect - table:', table);
        console.log('[DatabaseService] querySelect - options:', JSON.stringify(options));
        console.log('[DatabaseService] querySelect - client state BEFORE check:', {
            hasClient: !!this.client,
            clientType: this.client?.constructor?.name,
            hasSupabaseUrl: !!this.client?.supabaseUrl,
            supabaseUrl: this.client?.supabaseUrl,
            hasSupabaseKey: !!this.client?.supabaseKey,
            clientKeys: this.client ? Object.keys(this.client) : []
        });
        console.log('[DatabaseService] querySelect - call stack:', new Error().stack?.split('\n').slice(1, 6).join('\n'));
        
        // Ensure client is initialized before using it
        if (!this.client) {
            console.log('[DatabaseService] ⚠️ Client not initialized in querySelect, initializing...');
            console.log('[DatabaseService] querySelect - calling initialize()...');
            const initStartTime = Date.now();
            try {
                await this.initialize();
                const initElapsed = Date.now() - initStartTime;
                console.log(`[DatabaseService] querySelect - initialize() completed in ${initElapsed}ms`);
            } catch (initError) {
                console.error('[DatabaseService] querySelect - initialize() failed:', initError);
                console.error('[DatabaseService] querySelect - init error stack:', initError.stack);
                return {
                    data: null,
                    error: {
                        message: `Failed to initialize DatabaseService: ${initError.message}`,
                        code: 'INITIALIZATION_FAILED',
                        status: 500,
                        originalError: initError.message
                    }
                };
            }
        }
        
        console.log('[DatabaseService] querySelect - client state AFTER initialization check:', {
            hasClient: !!this.client,
            clientType: this.client?.constructor?.name,
            hasSupabaseUrl: !!this.client?.supabaseUrl,
            supabaseUrl: this.client?.supabaseUrl,
            hasSupabaseKey: !!this.client?.supabaseKey,
            clientIsNull: this.client === null,
            clientIsUndefined: this.client === undefined
        });
        
        if (!this.client || !this.client.supabaseUrl) {
            const error = new Error('DatabaseService client not initialized');
            console.error('[DatabaseService] ❌ querySelect error - client still not initialized after initialize() call');
            console.error('[DatabaseService] querySelect - client value:', this.client);
            console.error('[DatabaseService] querySelect - client.supabaseUrl:', this.client?.supabaseUrl);
            console.error('[DatabaseService] querySelect - error details:', {
                message: error.message,
                clientNull: this.client === null,
                clientUndefined: this.client === undefined,
                supabaseUrlMissing: !this.client?.supabaseUrl
            });
            return {
                data: null,
                error: {
                    message: error.message,
                    code: 'CLIENT_NOT_INITIALIZED',
                    status: 500
                }
            };
        }
        
        console.log('[DatabaseService] querySelect - building URL with supabaseUrl:', this.client.supabaseUrl);
        const url = new URL(`${this.client.supabaseUrl}/rest/v1/${table}`);
        
        // Add query parameters
        if (options.select) {
            url.searchParams.append('select', options.select);
        }
        if (options.filter) {
            console.log('[DatabaseService] querySelect - Applying filters to URL');
            this._applyFiltersToUrl(url, options.filter);
        }
        if (options.order) {
            options.order.forEach(({ column, ascending }) => {
                url.searchParams.append('order', `${column}.${ascending ? 'asc' : 'desc'}`);
            });
        }
        if (options.limit) {
            url.searchParams.append('limit', options.limit);
        }
        
        console.log(`[DatabaseService] querySelect URL: ${url.toString()}`);
        
        console.log('[DatabaseService] querySelect - client state BEFORE fetch:', {
            hasClient: !!this.client,
            hasSupabaseUrl: !!this.client?.supabaseUrl,
            supabaseUrl: this.client?.supabaseUrl
        });
        
        console.log('[DatabaseService] querySelect - calling _getAuthHeaders()...');
        let authHeaders;
        try {
            authHeaders = this._getAuthHeaders();
            console.log('[DatabaseService] querySelect - _getAuthHeaders() succeeded');
        } catch (headerError) {
            console.error('[DatabaseService] ❌ querySelect - _getAuthHeaders() failed:', headerError);
            console.error('[DatabaseService] querySelect - header error stack:', headerError.stack);
            return {
                data: null,
                count: null,
                error: {
                    message: `Failed to get auth headers: ${headerError.message}`,
                    code: 'AUTH_HEADERS_FAILED',
                    status: 500,
                    originalError: headerError.message
                }
            };
        }
        
        console.log('[DatabaseService] querySelect - calling fetch()...');
        console.log('[DatabaseService] querySelect - fetch URL:', url.toString());
        console.log('[DatabaseService] querySelect - fetch headers:', {
            hasApikey: !!authHeaders.apikey,
            hasAuthorization: !!authHeaders.Authorization,
            authorizationLength: authHeaders.Authorization?.length,
            authorizationPrefix: authHeaders.Authorization?.substring(0, 20)
        });
        
        const fetchStartTime = Date.now();
        let response;
        try {
            response = await fetch(url.toString(), {
                method: 'GET',
                headers: authHeaders
            });
        } catch (fetchError) {
            const fetchElapsed = Date.now() - fetchStartTime;
            console.error(`[DatabaseService] ❌ querySelect - fetch() FAILED after ${fetchElapsed}ms:`, fetchError);
            console.error('[DatabaseService] querySelect - fetch error details:', {
                name: fetchError.name,
                message: fetchError.message,
                stack: fetchError.stack,
                isCorsError: fetchError.message?.includes('CORS') || fetchError.message?.includes('access control'),
                isNetworkError: fetchError.message?.includes('Load failed') || fetchError.message?.includes('Failed to fetch')
            });
            console.error('[DatabaseService] querySelect - fetch error - URL was:', url.toString());
            console.error('[DatabaseService] querySelect - fetch error - client state:', {
                hasClient: !!this.client,
                hasSupabaseUrl: !!this.client?.supabaseUrl
            });
            return {
                data: null,
                error: {
                    message: `Fetch failed: ${fetchError.message}`,
                    code: 'FETCH_FAILED',
                    status: 0,
                    isCorsError: fetchError.message?.includes('CORS') || fetchError.message?.includes('access control'),
                    originalError: fetchError.message
                }
            };
        }
        
        const fetchElapsed = Date.now() - fetchStartTime;
        console.log(`[DatabaseService] querySelect - fetch() completed in ${fetchElapsed}ms`);
        console.log(`[DatabaseService] querySelect response status: ${response.status} ${response.statusText}`);
        console.log('[DatabaseService] querySelect - response headers:', {
            contentType: response.headers.get('content-type'),
            contentLength: response.headers.get('content-length'),
            contentRange: response.headers.get('content-range'),
            status: response.status,
            statusText: response.statusText,
            ok: response.ok
        });
        
        console.log('[DatabaseService] querySelect - client state AFTER fetch:', {
            hasClient: !!this.client,
            hasSupabaseUrl: !!this.client?.supabaseUrl,
            supabaseUrl: this.client?.supabaseUrl
        });
        
        console.log('[DatabaseService] querySelect - calling _handleResponse()...');
        const result = await this._handleResponse(response);
        console.log(`[DatabaseService] querySelect result:`, {
            hasData: result.data !== null && result.data !== undefined,
            dataType: typeof result.data,
            isArray: Array.isArray(result.data),
            dataLength: Array.isArray(result.data) ? result.data.length : 'N/A',
            hasError: result.error !== null,
            errorMessage: result.error?.message,
            errorCode: result.error?.code
        });
        
        console.log('[DatabaseService] querySelect - client state BEFORE return:', {
            hasClient: !!this.client,
            hasSupabaseUrl: !!this.client?.supabaseUrl
        });
        console.log('[DatabaseService] ========== querySelect COMPLETE ==========');
        
        return result;
    },
    
    /**
     * Execute an INSERT/UPSERT operation
     * @param {string} table - Table name
     * @param {Object|Array} data - Data to insert/upsert
     * @param {Object} options - Upsert options (onConflict, etc.)
     * @returns {Promise<{data: Array|null, error: Object|null}>}
     */
    async queryUpsert(table, data, options = {}) {
        // Try PATCH first (update if exists), then POST (insert if not)
        const { year, month, user_id } = options.filter || {};
        const identifier = options.identifier || 'id';
        const identifierValue = options.identifierValue;
        
        if (year !== undefined && month !== undefined) {
            // For months table - use year/month as identifier
            // For user_months, also include user_id in filter
            const patchUrl = new URL(`${this.client.supabaseUrl}/rest/v1/${table}`);
            patchUrl.searchParams.append('year', `eq.${year}`);
            patchUrl.searchParams.append('month', `eq.${month}`);
            if (user_id !== undefined && (table === 'user_months' || table === this._getTableName('userMonths'))) {
                patchUrl.searchParams.append('user_id', `eq.${user_id}`);
            }
            patchUrl.searchParams.append('select', '*');
            
            let response = await fetch(patchUrl.toString(), {
                method: 'PATCH',
                headers: this._getAuthHeaders(),
                body: JSON.stringify(data)
            });
            
            const patchStatus = response.status;
            const patchStatusText = response.statusText;
            console.log(`[DatabaseService] PATCH response status: ${patchStatus} ${patchStatusText}`);
            
            // Read response body to check if PATCH actually updated anything
            let patchResult = null;
            if (response.ok) {
                const patchText = await response.text();
                console.log(`[DatabaseService] PATCH response body (first 200 chars):`, patchText.substring(0, 200));
                console.log(`[DatabaseService] PATCH response body length:`, patchText.length);
                if (patchText && patchText.trim() !== '' && patchText.trim() !== '[]') {
                    try {
                        const patchData = JSON.parse(patchText);
                        console.log(`[DatabaseService] PATCH returned data:`, Array.isArray(patchData) ? `${patchData.length} items` : 'single object');
                        if (Array.isArray(patchData) && patchData.length > 0) {
                            // PATCH succeeded and returned data
                            patchResult = { data: patchData, error: null };
                        } else if (!Array.isArray(patchData) && patchData) {
                            // Single object returned
                            patchResult = { data: [patchData], error: null };
                        } else {
                            // Empty array - no rows updated, need to POST
                            console.log(`[DatabaseService] PATCH returned empty array - no rows matched, will try POST`);
                        }
                    } catch (e) {
                        console.warn(`[DatabaseService] PATCH response not JSON:`, patchText.substring(0, 100), e);
                    }
                } else {
                    console.log(`[DatabaseService] PATCH returned empty body or empty array - will try POST`);
                }
            }
            
            // If PATCH didn't work or returned empty, try POST for insert
            if (!response.ok || response.status === 404 || !patchResult) {
                console.log(`[DatabaseService] Trying POST for insert...`);
                const postUrl = new URL(`${this.client.supabaseUrl}/rest/v1/${table}`);
                response = await fetch(postUrl.toString(), {
                    method: 'POST',
                    headers: this._getAuthHeaders(),
                    body: JSON.stringify(data)
                });
                const postStatus = response.status;
                const postStatusText = response.statusText;
                console.log(`[DatabaseService] POST response status: ${postStatus} ${postStatusText}`);
                
                // Read POST response body
                if (response.ok) {
                    const postText = await response.text();
                    console.log(`[DatabaseService] POST response body (first 200 chars):`, postText.substring(0, 200));
                    console.log(`[DatabaseService] POST response body length:`, postText.length);
                    if (postText && postText.trim() !== '' && postText.trim() !== '[]') {
                        try {
                            const postData = JSON.parse(postText);
                            console.log(`[DatabaseService] POST returned data:`, Array.isArray(postData) ? `${postData.length} items` : 'single object');
                            patchResult = Array.isArray(postData) ? { data: postData, error: null } : { data: [postData], error: null };
                        } catch (e) {
                            console.warn(`[DatabaseService] POST response not JSON:`, postText.substring(0, 100), e);
                            // Try to parse as error
                            patchResult = await this._handleResponse(new Response(postText, {
                                status: response.status,
                                statusText: response.statusText,
                                headers: response.headers
                            }));
                        }
                    } else {
                        console.warn(`[DatabaseService] POST returned empty body or empty array`);
                        // Empty response - might be RLS blocking return representation
                        patchResult = { data: [], error: null };
                    }
                } else {
                    // POST failed - use _handleResponse to get error
                    patchResult = await this._handleResponse(response);
                }
            }
            
            console.log(`[DatabaseService] queryUpsert final result:`, {
                hasData: patchResult && patchResult.data !== null && patchResult.data !== undefined,
                dataType: patchResult && typeof patchResult.data,
                isArray: patchResult && Array.isArray(patchResult.data),
                dataLength: patchResult && Array.isArray(patchResult.data) ? patchResult.data.length : 'N/A',
                hasError: patchResult && patchResult.error !== null,
                error: patchResult && patchResult.error
            });
            
            return patchResult || { data: null, error: { message: 'Upsert failed - no response' } };
            
            const result = await this._handleResponse(response);
            console.log(`[DatabaseService] queryUpsert result:`, {
                hasData: result.data !== null && result.data !== undefined,
                dataType: typeof result.data,
                isArray: Array.isArray(result.data),
                dataLength: Array.isArray(result.data) ? result.data.length : 'N/A',
                hasError: result.error !== null,
                error: result.error
            });
            
            return result;
        } else if (identifierValue !== undefined) {
            // For settings/subscriptions table - use user_id as identifier
            const patchUrl = new URL(`${this.client.supabaseUrl}/rest/v1/${table}`);
            patchUrl.searchParams.append(identifier, `eq.${identifierValue}`);
            patchUrl.searchParams.append('select', '*');
            
            // Add Prefer header to return updated data (required for subscriptions table)
            const patchHeaders = this._getAuthHeaders();
            patchHeaders['Prefer'] = 'return=representation';
            
            let response = await fetch(patchUrl.toString(), {
                method: 'PATCH',
                headers: patchHeaders,
                body: JSON.stringify(data)
            });
            
            const patchStatus = response.status;
            const patchOk = response.ok;
            
            // Check if PATCH actually updated a row by reading the response
            let patchUpdatedRow = false;
            if (patchOk && patchStatus === 200) {
                const responseClone = response.clone();
                const patchResponseText = await responseClone.text();
                console.log(`[DatabaseService] PATCH response body:`, patchResponseText);
                
                if (patchResponseText && patchResponseText.trim() !== '' && patchResponseText.trim() !== '[]') {
                    try {
                        const patchResponseData = JSON.parse(patchResponseText);
                        const isArray = Array.isArray(patchResponseData);
                        const hasData = isArray ? patchResponseData.length > 0 : !!patchResponseData;
                        console.log(`[DatabaseService] PATCH returned data:`, isArray ? `${patchResponseData.length} items` : 'single object', hasData ? patchResponseData : 'empty');
                        patchUpdatedRow = hasData;
                    } catch (e) {
                        console.warn(`[DatabaseService] PATCH response not valid JSON:`, patchResponseText.substring(0, 200));
                    }
                } else {
                    console.log(`[DatabaseService] PATCH returned empty body - no rows matched, will try POST`);
                    patchUpdatedRow = false;
                }
            }
            
            if (!patchOk || patchStatus === 404 || !patchUpdatedRow) {
                // Try POST for insert (either PATCH failed or no rows were updated)
                console.log(`[DatabaseService] PATCH ${patchUpdatedRow ? 'updated row' : 'did not match any rows'} (status: ${patchStatus}), trying POST for insert...`);
                const postUrl = new URL(`${this.client.supabaseUrl}/rest/v1/${table}`);
                // Ensure identifier is in the data (data already has it, but be explicit)
                const postData = { ...data };
                if (!postData[identifier]) {
                    postData[identifier] = identifierValue;
                }
                console.log(`[DatabaseService] POST body for ${table}:`, JSON.stringify(postData));
                response = await fetch(postUrl.toString(), {
                    method: 'POST',
                    headers: this._getAuthHeaders(),
                    body: JSON.stringify(postData)
                });
                const postStatus = response.status;
                console.log(`[DatabaseService] POST response status: ${postStatus}`);
                if (postStatus === 201 || postStatus === 200) {
                    const postResponseClone = response.clone();
                    const postResponseText = await postResponseClone.text();
                    console.log(`[DatabaseService] POST response body:`, postResponseText);
                }
            }
            
            const result = await this._handleResponse(response);
            
            // Check for column existence errors
            if (result.error && result.error.message && result.error.message.includes('does not exist')) {
                console.error(`[DatabaseService] Database schema error: ${result.error.message}`);
                console.error(`[DatabaseService] The ${table} table may be missing the ${identifier} column. Please run the migration script.`);
            }
            
            return result;
        } else {
            // Simple POST for new records
            const postUrl = new URL(`${this.client.supabaseUrl}/rest/v1/${table}`);
            const response = await fetch(postUrl.toString(), {
                method: 'POST',
                headers: this._getAuthHeaders(),
                body: JSON.stringify(data)
            });
            
            return await this._handleResponse(response);
        }
    },
    
    /**
     * Execute a DELETE operation
     * @param {string} table - Table name
     * @param {Object} filter - Filter conditions
     * @returns {Promise<{data: Array|null, error: Object|null}>}
     */
    async queryDelete(table, filter = {}) {
        const deleteUrl = new URL(`${this.client.supabaseUrl}/rest/v1/${table}`);
        deleteUrl.searchParams.append('select', '*');
        
        // Add filter conditions
        Object.entries(filter).forEach(([key, value]) => {
            deleteUrl.searchParams.append(key, `eq.${value}`);
        });
        
        const response = await fetch(deleteUrl.toString(), {
            method: 'DELETE',
            headers: this._getAuthHeaders()
        });
        
        return await this._handleResponse(response);
    },
    
    /**
     * Execute an INSERT operation
     * @param {string} table - Table name
     * @param {Object|Array} data - Data to insert
     * @returns {Promise<{data: Array|null, error: Object|null}>}
     */
    async queryInsert(table, data) {
        const insertUrl = new URL(`${this.client.supabaseUrl}/rest/v1/${table}`);
        insertUrl.searchParams.append('select', '*');
        
        const response = await fetch(insertUrl.toString(), {
            method: 'POST',
            headers: this._getAuthHeaders(),
            body: JSON.stringify(data)
        });
        
        return await this._handleResponse(response);
    },
    
    /**
     * Execute an RPC (Remote Procedure Call) to a database function
     * @param {string} functionName - Function name
     * @param {Object} params - Function parameters
     * @returns {Promise<{data: any|null, error: Object|null}>}
     */
    async queryRpc(functionName, params = {}) {
        console.log('[DatabaseService] ========== queryRpc CALLED ==========');
        console.log('[DatabaseService] queryRpc - function:', functionName);
        console.log('[DatabaseService] queryRpc - params:', JSON.stringify(params));

        if (!this.client) {
            console.log('[DatabaseService] Client not initialized, initializing...');
            await this.initialize();
        }

        if (!this.client || !this.client.supabaseUrl) {
            return {
                data: null,
                error: {
                    message: 'Database client not initialized',
                    status: 500
                }
            };
        }

        const rpcUrl = new URL(`${this.client.supabaseUrl}/rest/v1/rpc/${functionName}`);
        console.log('[DatabaseService] queryRpc URL:', rpcUrl.toString());

        const authHeaders = this._getAuthHeaders();
        console.log('[DatabaseService] queryRpc - calling fetch()...');

        try {
            const response = await fetch(rpcUrl.toString(), {
                method: 'POST',
                headers: {
                    ...authHeaders,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(params)
            });

            const responseText = await response.text();
            console.log('[DatabaseService] queryRpc response status:', response.status, response.statusText);
            console.log('[DatabaseService] queryRpc response body:', responseText.substring(0, 200));

            if (!response.ok) {
                let errorObj;
                try {
                    errorObj = JSON.parse(responseText);
                } catch {
                    errorObj = { message: responseText };
                }
                return {
                    data: null,
                    error: {
                        message: errorObj.message || responseText,
                        code: errorObj.code,
                        details: errorObj.details,
                        hint: errorObj.hint,
                        status: response.status
                    }
                };
            }

            let data = null;
            if (responseText && responseText.trim() !== '') {
                try {
                    data = JSON.parse(responseText);
                } catch (e) {
                    console.warn('[DatabaseService] queryRpc response not JSON:', responseText.substring(0, 100));
                    data = responseText;
                }
            }

            console.log('[DatabaseService] ========== queryRpc COMPLETE ==========');
            return {
                data: data,
                error: null
            };
        } catch (error) {
            console.error('[DatabaseService] Exception in queryRpc:', error);
            return {
                data: null,
                error: {
                    message: error.message || 'An unexpected error occurred',
                    status: 500
                }
            };
        }
    },

    /**
     * Execute an UPDATE operation
     * @param {string} table - Table name
     * @param {string|number|null} id - Record ID to update (null for bulk updates with filter)
     * @param {Object} updateData - Data to update
     * @param {Object} filter - Optional filter object for bulk updates (when id is null)
     * @returns {Promise<{data: Array|null, error: Object|null}>}
     */
    async queryUpdate(table, id, updateData, filter = null) {
        console.log('[DatabaseService] ========== queryUpdate CALLED ==========');
        console.log('[DatabaseService] queryUpdate - table:', table);
        console.log('[DatabaseService] queryUpdate - id:', id, 'type:', typeof id);
        console.log('[DatabaseService] queryUpdate - updateData:', JSON.stringify(updateData, null, 2));
        console.log('[DatabaseService] queryUpdate - filter:', filter ? JSON.stringify(filter, null, 2) : 'null');
        
        const updateUrl = new URL(`${this.client.supabaseUrl}/rest/v1/${table}`);
        
        if (id !== null && id !== undefined) {
            console.log('[DatabaseService] queryUpdate - Using id-based update:', id);
            updateUrl.searchParams.append('id', `eq.${id}`);
        } else if (filter) {
            console.log('[DatabaseService] queryUpdate - Using filter-based bulk update');
            this._applyFiltersToUrl(updateUrl, filter);
        } else {
            console.error('[DatabaseService] queryUpdate - ERROR: Both id and filter are null/undefined. Cannot perform update.');
            return {
                data: null,
                count: null,
                error: {
                    message: 'Either id or filter must be provided for update operation',
                    status: 400
                }
            };
        }
        
        updateUrl.searchParams.append('select', '*');
        
        console.log('[DatabaseService] queryUpdate - URL:', updateUrl.toString());
        
        const authHeaders = this._getAuthHeaders();
        const headers = {
            ...authHeaders,
            'Prefer': 'return=representation' // This is required for Supabase to return the updated rows
        };
        
        console.log('[DatabaseService] queryUpdate - headers:', {
            hasApikey: !!headers.apikey,
            hasAuthorization: !!headers.Authorization,
            hasPrefer: !!headers.Prefer,
            preferValue: headers.Prefer
        });
        
        console.log('[DatabaseService] queryUpdate - calling fetch()...');
        const fetchStartTime = Date.now();
        const response = await fetch(updateUrl.toString(), {
            method: 'PATCH',
            headers: headers,
            body: JSON.stringify(updateData)
        });
        const fetchDuration = Date.now() - fetchStartTime;
        
        console.log(`[DatabaseService] queryUpdate - fetch() completed in ${fetchDuration}ms`);
        console.log('[DatabaseService] queryUpdate - response status:', response.status, response.statusText);
        console.log('[DatabaseService] queryUpdate - response headers:', {
            contentType: response.headers.get('content-type'),
            contentRange: response.headers.get('content-range'),
            contentLength: response.headers.get('content-length')
        });
        
        // Clone response for logging (can only read body once)
        const responseClone = response.clone();
        try {
            const responseText = await responseClone.text();
            console.log('[DatabaseService] queryUpdate - response body (first 500 chars):', responseText.substring(0, 500));
        } catch (e) {
            console.warn('[DatabaseService] queryUpdate - Could not read response body for logging:', e.message);
        }
        
        const result = await this._handleResponse(response);
        
        console.log('[DatabaseService] queryUpdate - result:', {
            hasError: !!result.error,
            error: result.error,
            hasData: !!result.data,
            dataLength: result.data?.length || 0,
            dataType: Array.isArray(result.data) ? 'array' : typeof result.data
        });
        console.log('[DatabaseService] ========== queryUpdate COMPLETE ==========');
        
        return result;
    },

    /**
     * Apply filters to URL for PostgREST queries
     * @private
     * @param {URL} url - URL object to modify
     * @param {Object} filter - Filter object
     */
    _applyFiltersToUrl(url, filter) {
        console.log('[DatabaseService] _applyFiltersToUrl() called', { filter: JSON.stringify(filter, null, 2) });
        
        if (!filter || typeof filter !== 'object') {
            console.warn('[DatabaseService] _applyFiltersToUrl - Invalid filter provided:', filter);
            return;
        }
        
        // Handle $or filter for PostgREST
        if (filter.$or && Array.isArray(filter.$or)) {
            console.log('[DatabaseService] _applyFiltersToUrl - Processing $or filter');
            // Convert $or array to PostgREST or syntax: or=(condition1,condition2)
            const orConditions = filter.$or.map(condition => {
                // Each condition should be an object like { user1_id: userId }
                // For PostgREST, each condition in or() should be a single column comparison
                const conditionEntries = Object.entries(condition);
                if (conditionEntries.length !== 1) {
                    throw new Error(`Each $or condition must have exactly one key-value pair, got ${conditionEntries.length}`);
                }
                const [key, value] = conditionEntries[0];
                return `${key}.eq.${value}`;
            });
            url.searchParams.append('or', `(${orConditions.join(',')})`);
            console.log('[DatabaseService] _applyFiltersToUrl - converted $or filter to PostgREST or syntax:', `or=(${orConditions.join(',')})`);
            
            // Also process other filters (if any)
            Object.entries(filter).forEach(([key, value]) => {
                if (key !== '$or') {
                    url.searchParams.append(key, `eq.${value}`);
                    console.log('[DatabaseService] _applyFiltersToUrl - Added filter:', key, '=', value);
                }
            });
        } else {
            // Regular filters (no $or)
            console.log('[DatabaseService] _applyFiltersToUrl - Processing regular filters');
            Object.entries(filter).forEach(([key, value]) => {
                url.searchParams.append(key, `eq.${value}`);
                console.log('[DatabaseService] _applyFiltersToUrl - Added filter:', key, '=', value);
            });
        }
        
        console.log('[DatabaseService] _applyFiltersToUrl - Final URL:', url.toString());
    },
    
    /**
     * Handle HTTP response and convert to standard format
     * @private
     */
    async _handleResponse(response) {
        if (!response.ok) {
            // Parse error response first to check error type
            const errorText = await response.text();
            let errorObj;
            try {
                errorObj = JSON.parse(errorText);
            } catch {
                errorObj = { message: errorText };
            }

            // Check for authentication failures (401 Unauthorized, 403 Forbidden)
            // BUT: Distinguish RLS policy violations (code 42501) from auth failures
            if (response.status === 401 || response.status === 403) {
                // PostgreSQL error code 42501 = "insufficient privilege" (RLS violation)
                // This is NOT an auth failure - it's a permissions/policy issue
                if (errorObj.code === '42501') {
                    console.warn('[DatabaseService] RLS policy violation (code 42501):', errorObj.message);
                    console.warn('[DatabaseService] This is a permissions issue, not an auth failure');
                    // Don't redirect - just return the error for proper handling
                } else {
                    // True authentication failure - redirect to sign-in
                    console.warn('[DatabaseService] Authentication failed on server (status:', response.status, ')');
                    console.warn('[DatabaseService] This indicates the auth token is invalid or expired');
                    console.warn('[DatabaseService] Redirecting to sign-in...');

                    // Clear validation cache in AuthService to force fresh check
                    if (window.AuthService) {
                        window.AuthService.lastValidation = { timestamp: 0, result: null };
                        // Redirect to sign-in
                        window.AuthService._redirectToSignIn();
                    }
                }
            }

            return {
                data: null,
                count: null,
                error: {
                    message: errorObj.message || errorText,
                    code: errorObj.code,
                    details: errorObj.details,
                    hint: errorObj.hint,
                    status: response.status
                }
            };
        }
        
        // Extract count from Content-Range header if present (for count: 'exact' queries)
        let count = null;
        const contentRange = response.headers.get('content-range');
        if (contentRange) {
            // Content-Range format: "0-4/5" where 5 is the total count
            const match = contentRange.match(/\/(\d+)$/);
            if (match) {
                count = parseInt(match[1], 10);
                console.log('[DatabaseService] _handleResponse - Extracted count from Content-Range header:', {
                    contentRange: contentRange,
                    extractedCount: count
                });
            }
        }
        
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            const text = await response.text();
            if (!text || text.trim() === '') {
                return { data: null, count: count || 0, error: null };
            }
            try {
                const data = JSON.parse(text);
                // If count wasn't extracted from header but we have data, use data length as fallback
                if (count === null && Array.isArray(data)) {
                    count = data.length;
                    console.log('[DatabaseService] _handleResponse - Using data length as count:', count);
                }
                return { data, count: count || (Array.isArray(data) ? data.length : null), error: null };
            } catch (e) {
                return { data: null, count: null, error: { message: 'Invalid JSON response', status: response.status } };
            }
        }
        
        return { data: null, count: null, error: null };
    },
    
    /**
     * Check if a month key is example data (protected)
     * Checks if the month exists in the example_months table
     * @param {string} monthKey - Month key
     * @returns {Promise<boolean>} True if example data
     */
    async isExampleData(monthKey) {
        try {
            console.log(`[DatabaseService] isExampleData() called for: ${monthKey}`);
            
            if (!this.client) {
                console.log('[DatabaseService] Client not initialized, initializing...');
                await this.initialize();
            }
            
            const { year, month } = this.parseMonthKey(monthKey);
            console.log(`[DatabaseService] Checking example_months for year=${year}, month=${month}...`);
            
            const { data, error } = await this.querySelect(this._getTableName('exampleMonths'), {
                select: 'id',
                filter: { year: year, month: month },
                limit: 1
            });
            
            if (error) {
                if (error.code === 'PGRST116' || error.status === 404) {
                    console.log(`[DatabaseService] ${monthKey} not found in example_months - not example data`);
                    return false; // Not found in example_months
                }
                console.error(`[DatabaseService] Error checking example_months:`, error);
                return false;
            }
            
            const isExample = data !== null && Array.isArray(data) && data.length > 0;
            console.log(`[DatabaseService] ${monthKey} isExampleData result: ${isExample}`);
            return isExample;
        } catch (error) {
            console.warn(`[DatabaseService] Error checking if ${monthKey} is example data:`, error);
            return false;
        }
    },
    
    /**
     * Synchronous version of isExampleData for backward compatibility
     * Uses year check as fallback if database check fails
     * @param {string} monthKey - Month key
     * @returns {boolean} True if example data (based on year)
     */
    isExampleDataSync(monthKey) {
        try {
            const { year } = this.parseMonthKey(monthKey);
            return year === this.EXAMPLE_YEAR;
        } catch (error) {
            return false;
        }
    },
    
    /**
     * Get the table name for a month based on whether it's example data
     * @param {string} monthKey - Month key
     * @returns {Promise<string>} Table name ('example_months' or 'user_months')
     */
    async getTableName(monthKey) {
        console.log(`[DatabaseService] getTableName() called for: ${monthKey}`);
        const isExample = await this.isExampleData(monthKey);
        const tableKey = isExample ? 'exampleMonths' : 'userMonths';
        const tableName = this._getTableName(tableKey);
        console.log(`[DatabaseService] getTableName() result for ${monthKey}: ${tableName}`);
        return tableName;
    },
    
    /**
     * Load cache from localStorage
     * @returns {Object|null} Cached months or null
     */
    loadCacheFromStorage() {
        try {
            const cachedData = localStorage.getItem(this.CACHE_STORAGE_KEY);
            const cachedTimestamp = localStorage.getItem(this.CACHE_TIMESTAMP_KEY);
            
            if (cachedData && cachedTimestamp) {
                const timestamp = parseInt(cachedTimestamp, 10);
                const now = Date.now();
                
                // Check if cache is still valid (within 24 hours)
                if (now - timestamp < this.CACHE_DURATION) {
                    return JSON.parse(cachedData);
                }
            }
        } catch (error) {
            console.warn('Error loading cache from storage:', error);
        }
        return null;
    },
    
    /**
     * Save cache to localStorage
     * @param {Object} monthsData - Months data object
     */
    saveCacheToStorage(monthsData) {
        try {
            localStorage.setItem(this.CACHE_STORAGE_KEY, JSON.stringify(monthsData));
            localStorage.setItem(this.CACHE_TIMESTAMP_KEY, Date.now().toString());
        } catch (error) {
            console.warn('Error saving cache to storage:', error);
        }
    },
    
    /**
     * Clear cache (both memory and storage)
     * Also clears settings cache
     */
    clearCache() {
        console.log('[DatabaseService] clearCache() called');
        this.monthsCache = null;
        this.cacheTimestamp = null;
        this.settingsCache = null;
        this.settingsCacheUserId = null;
        this.settingsCachePromise = null;
        try {
            localStorage.removeItem(this.CACHE_STORAGE_KEY);
            localStorage.removeItem(this.CACHE_TIMESTAMP_KEY);
            console.log('[DatabaseService] Cache cleared from memory and localStorage');
        } catch (error) {
            console.warn('[DatabaseService] Error clearing cache from storage:', error);
        }
    },
    
    /**
     * Clear example months from cache only (not from database)
     * Uses year-based check for faster performance
     * @returns {Promise<void>}
     */
    async clearExampleDataFromCache() {
        try {
            console.log('[DatabaseService] clearExampleDataFromCache() called');
            
            // Clear from memory cache using year-based check (faster than database queries)
            if (this.monthsCache) {
                const exampleMonthKeys = [];
                for (const monthKey of Object.keys(this.monthsCache)) {
                    // Use year-based check for performance (example data is year 2045)
                    const { year } = this.parseMonthKey(monthKey);
                    if (year === this.EXAMPLE_YEAR) {
                        exampleMonthKeys.push(monthKey);
                    }
                }
                console.log(`[DatabaseService] Clearing ${exampleMonthKeys.length} example months from in-memory cache:`, exampleMonthKeys);
                exampleMonthKeys.forEach(monthKey => {
                    delete this.monthsCache[monthKey];
                });
            }
            
            // Clear from localStorage cache (if it exists)
            const cachedData = localStorage.getItem(this.CACHE_STORAGE_KEY);
            if (cachedData) {
                try {
                    const monthsCache = JSON.parse(cachedData);
                    const exampleMonthKeys = [];
                    
                    // Use year-based check for performance
                    for (const monthKey of Object.keys(monthsCache)) {
                        try {
                            const { year } = this.parseMonthKey(monthKey);
                            if (year === this.EXAMPLE_YEAR) {
                                exampleMonthKeys.push(monthKey);
                            }
                        } catch (error) {
                            // Skip invalid month keys
                            continue;
                        }
                    }
                    
                    console.log(`[DatabaseService] Clearing ${exampleMonthKeys.length} example months from localStorage cache:`, exampleMonthKeys);
                    exampleMonthKeys.forEach(monthKey => {
                        delete monthsCache[monthKey];
                    });
                    
                    localStorage.setItem(this.CACHE_STORAGE_KEY, JSON.stringify(monthsCache));
                    localStorage.setItem(this.CACHE_TIMESTAMP_KEY, Date.now().toString());
                } catch (error) {
                    console.warn('[DatabaseService] Error processing cache:', error);
                    // If cache is corrupted, just remove it
                    localStorage.removeItem(this.CACHE_STORAGE_KEY);
                    localStorage.removeItem(this.CACHE_TIMESTAMP_KEY);
                }
            }
            
            console.log('[DatabaseService] clearExampleDataFromCache() completed');
        } catch (error) {
            console.error('[DatabaseService] Error clearing example data from cache:', error);
            throw error;
        }
    },
    
    /**
     * Initialize database service with Supabase client
     * @returns {Promise<boolean>} Success status
     */
    async initialize() {
        const initStartTime = Date.now();
        console.log('[DatabaseService] ========== initialize() CALLED ==========');
        console.log('[DatabaseService] DatabaseService VERSION:', this.VERSION || 'UNKNOWN');
        console.log('[DatabaseService] initialize - call stack:', new Error().stack?.split('\n').slice(1, 6).join('\n'));
        console.log('[DatabaseService] initialize - client state BEFORE:', {
            hasClient: !!this.client,
            clientType: this.client?.constructor?.name,
            clientIsNull: this.client === null,
            clientIsUndefined: this.client === undefined
        });
        
        try {
            console.log('[DatabaseService] Initializing...');
            
            // Try to get client from config system first
            let client = null;
            
            if (this._config && typeof DatabaseConfigHelper !== 'undefined') {
                try {
                    const providerType = DatabaseConfigHelper.getProviderType(this);
                    console.log('[DatabaseService] Provider type from config:', providerType);
                    
                    if (providerType === 'supabase') {
                        // For Supabase, we still use SupabaseConfig to get the client
                        // This allows us to swap out the provider in the future
                        if (!window.SupabaseConfig) {
                            throw new Error('SupabaseConfig not available for Supabase provider');
                        }
                        console.log('[DatabaseService] initialize - calling SupabaseConfig.getClient() (via config)...');
                        client = window.SupabaseConfig.getClient();
                    } else {
                        throw new Error(`Unsupported provider type: ${providerType}`);
                    }
                } catch (configError) {
                    console.warn('[DatabaseService] Could not get client from config, falling back to SupabaseConfig:', configError.message);
                }
            }
            
            // Fallback to direct SupabaseConfig for backward compatibility
            if (!client) {
                if (!window.SupabaseConfig) {
                    const error = new Error('SupabaseConfig not available and no config provided');
                    console.error('[DatabaseService] ❌ initialize error - SupabaseConfig not available');
                    throw error;
                }
                
                console.log('[DatabaseService] initialize - calling SupabaseConfig.getClient() (fallback)...');
                client = window.SupabaseConfig.getClient();
            }
            
            this.client = client;
            console.log('[DatabaseService] initialize - getClient() returned:', {
                hasClient: !!this.client,
                clientType: this.client?.constructor?.name,
                hasSupabaseUrl: !!this.client?.supabaseUrl,
                supabaseUrl: this.client?.supabaseUrl,
                hasSupabaseKey: !!this.client?.supabaseKey,
                supabaseKeyLength: this.client?.supabaseKey?.length,
                clientIsNull: this.client === null,
                clientIsUndefined: this.client === undefined
            });
            console.log('[DatabaseService] Supabase client obtained:', this.client ? 'Success' : 'Failed');
            
            if (!this.client) {
                const error = new Error('Failed to initialize Supabase client - getClient() returned null/undefined');
                console.error('[DatabaseService] ❌ initialize error:', error);
                throw error;
            }
            
            console.log('[DatabaseService] initialize - client state AFTER assignment:', {
                hasClient: !!this.client,
                clientType: this.client?.constructor?.name,
                hasSupabaseUrl: !!this.client?.supabaseUrl,
                supabaseUrl: this.client?.supabaseUrl,
                hasSupabaseKey: !!this.client?.supabaseKey
            });
            
            // Test the client connection - check if we can reach Supabase at all
            console.log('[DatabaseService] Testing Supabase connection...');
            console.log('[DatabaseService] Supabase URL:', window.SupabaseConfig?.PROJECT_URL);
            console.log('[DatabaseService] API Key present:', !!window.SupabaseConfig?.PUBLISHABLE_API_KEY);
            console.log('[DatabaseService] API Key length:', window.SupabaseConfig?.PUBLISHABLE_API_KEY?.length);
            
            // Check if we can make a simple HTTP request to Supabase
            try {
                const supabaseUrl = window.SupabaseConfig?.PROJECT_URL;
                if (supabaseUrl) {
                    console.log('[DatabaseService] Testing HTTP connectivity to Supabase...');
                    const healthCheckUrl = `${supabaseUrl}/rest/v1/`;
                    
                    // Try a simple fetch to see if we can reach the server
                    const fetchStart = Date.now();
                    const fetchResult = await Promise.race([
                        fetch(healthCheckUrl, {
                            method: 'HEAD',
                            headers: {
                                'apikey': window.SupabaseConfig?.PUBLISHABLE_API_KEY || '',
                                'Authorization': `Bearer ${window.SupabaseConfig?.PUBLISHABLE_API_KEY || ''}`
                            }
                        }),
                        new Promise((_, reject) => setTimeout(() => reject(new Error('HTTP test timeout')), 5000))
                    ]).catch(err => {
                        const fetchElapsed = Date.now() - fetchStart;
                        console.error(`[DatabaseService] HTTP test failed after ${fetchElapsed}ms:`, err);
                        return null;
                    });
                    
                    if (fetchResult) {
                        const fetchElapsed = Date.now() - fetchStart;
                        console.log(`[DatabaseService] HTTP connectivity test successful (${fetchElapsed}ms) - Status: ${fetchResult.status}`);
            } else {
                        console.error('[DatabaseService] HTTP connectivity test failed - cannot reach Supabase server');
                        console.error('[DatabaseService] Possible issues:');
                        console.error('[DatabaseService] 1. Network connectivity problem');
                        console.error('[DatabaseService] 2. CORS policy blocking requests');
                        console.error('[DatabaseService] 3. Supabase project URL is incorrect');
                        console.error('[DatabaseService] 4. Supabase project is paused or deleted');
                        console.error('[DatabaseService] 5. Firewall/proxy blocking requests');
                    }
                }
            } catch (httpTestError) {
                console.warn('[DatabaseService] HTTP connectivity test error:', httpTestError);
            }
            
            // Test the client with a simple query (with timeout)
            console.log('[DatabaseService] Testing Supabase client with query...');
            try {
                // First, try a direct fetch to see if we can reach the API
                console.log('[DatabaseService] Testing direct fetch to Supabase REST API...');
                const directFetchUrl = `${this.client.supabaseUrl}/rest/v1/user_months?select=id&limit=1`;
                console.log('[DatabaseService] Direct fetch URL:', directFetchUrl);
                
                try {
                    const directFetchResult = await Promise.race([
                        fetch(directFetchUrl, {
                            method: 'GET',
                            headers: this._getAuthHeaders()
                        }),
                        new Promise((_, reject) => setTimeout(() => reject(new Error('Direct fetch timeout')), 5000))
                    ]);
                    
                    console.log('[DatabaseService] Direct fetch completed - Status:', directFetchResult.status);
                    console.log('[DatabaseService] Direct fetch headers:', Object.fromEntries(directFetchResult.headers.entries()));
                    
                    if (directFetchResult.ok) {
                        const directData = await directFetchResult.json();
                        console.log('[DatabaseService] Direct fetch successful - data:', directData);
                    } else {
                        const errorText = await directFetchResult.text();
                        console.error('[DatabaseService] Direct fetch failed - Status:', directFetchResult.status);
                        console.error('[DatabaseService] Direct fetch error:', errorText);
                    }
                } catch (directFetchError) {
                    console.error('[DatabaseService] Direct fetch error:', directFetchError);
                }
                
                // Now try the Supabase client query
                console.log('[DatabaseService] Testing Supabase client query...');
                const testQuery = this.client.from(this._getTableName('userMonths')).select('id').limit(1);
                console.log('[DatabaseService] Test query created, testing connection...');
                console.log('[DatabaseService] Client object:', this.client);
                console.log('[DatabaseService] Client supabaseUrl:', this.client.supabaseUrl);
                console.log('[DatabaseService] Client supabaseKey present:', !!this.client.supabaseKey);
                console.log('[DatabaseService] Client type/version:', this.client.constructor?.name);
                
                // Set a short timeout for the test
                const testTimeout = setTimeout(() => {
                    console.warn('[DatabaseService] Query test timed out - queries are not completing');
                    console.warn('[DatabaseService] If direct fetch worked but client query didn\'t, there\'s an issue with the Supabase JS client');
                }, 3000);
                
                const testStartTime = Date.now();
                const testResult = await Promise.race([
                    testQuery,
                    new Promise((_, reject) => setTimeout(() => reject(new Error('Test timeout')), 3000))
                ]).catch(err => {
                    clearTimeout(testTimeout);
                    const elapsed = Date.now() - testStartTime;
                    if (err.message === 'Test timeout') {
                        console.error(`[DatabaseService] Query test failed after ${elapsed}ms - queries are timing out`);
                        console.error('[DatabaseService] If direct fetch worked, the Supabase JS client may have an issue');
                        console.error('[DatabaseService] Check: Supabase JS library version compatibility');
                    }
                    return { data: null, error: err };
                });
                
                clearTimeout(testTimeout);
                if (testResult && testResult.error) {
                    console.warn('[DatabaseService] Query test returned error:', testResult.error);
                    console.warn('[DatabaseService] Error code:', testResult.error.code);
                    console.warn('[DatabaseService] Error message:', testResult.error.message);
                } else if (testResult && testResult.data !== undefined) {
                    console.log('[DatabaseService] Query test successful - client is working');
                    console.log('[DatabaseService] Test result:', testResult);
                } else {
                    console.warn('[DatabaseService] Query test returned unexpected result:', testResult);
                }
            } catch (testError) {
                console.warn('[DatabaseService] Query test error:', testError);
                console.warn('[DatabaseService] Error stack:', testError.stack);
            }
            
            // Always initialize fresh - never load cache from localStorage
            // User data is always loaded from user_months table on every page load
            // Example data is loaded from example_months table
            // Cache is only used for example data clearing functionality (local only)
            const initElapsed = Date.now() - initStartTime;
            console.log(`[DatabaseService] ✅ Initialized successfully in ${initElapsed}ms - will fetch fresh data from database`);
            console.log('[DatabaseService] initialize - FINAL client state:', {
                hasClient: !!this.client,
                clientType: this.client?.constructor?.name,
                hasSupabaseUrl: !!this.client?.supabaseUrl,
                supabaseUrl: this.client?.supabaseUrl,
                hasSupabaseKey: !!this.client?.supabaseKey
            });
            console.log('[DatabaseService] ========== initialize() COMPLETE ==========');
            
            return true;
        } catch (error) {
            const initElapsed = Date.now() - initStartTime;
            console.error(`[DatabaseService] ❌ Error initializing after ${initElapsed}ms:`, error);
            console.error('[DatabaseService] initialize - error details:', {
                message: error.message,
                name: error.name,
                stack: error.stack
            });
            console.error('[DatabaseService] initialize - client state on error:', {
                hasClient: !!this.client,
                clientIsNull: this.client === null,
                clientIsUndefined: this.client === undefined
            });
            console.error('[DatabaseService] ========== initialize() FAILED ==========');
            throw error;
        }
    },
    
    /**
     * Get all months from database (always fetches fresh from database)
     * @param {boolean} forceRefresh - Deprecated, always fetches fresh
     * @returns {Promise<Object>} Object with all months keyed by monthKey
     */
    /**
     * Low-level direct fetch helper - bypasses Supabase JS client when it hangs
     * 
     * NOTE: This is a low-level helper method. All database operations should use
     * the centralized query interface methods (querySelect, queryUpsert, queryDelete)
     * instead of calling this directly. This method is kept for:
     * - Testing/debugging purposes
     * - Initialization connectivity tests
     * - Future migration if needed
     * 
     * We're using direct fetch instead of the Supabase JS client because:
     * - The Supabase JS client queries were hanging indefinitely (promises never resolving)
     * - Direct fetch works reliably and returns data immediately
     * - This ensures we always get fresh, accurate data from the database
     * 
     * The centralized query interface (querySelect, queryUpsert, queryDelete) uses
     * this method internally, so if we need to switch implementations in the future,
     * we only need to modify those three methods.
     * 
     * @private (kept public for testing/debugging, but prefer using querySelect/queryUpsert/queryDelete)
     */
    async directFetch(table, queryParams = {}) {
        const url = new URL(`${this.client.supabaseUrl}/rest/v1/${table}`);
        
        // Add query parameters for GET requests
        if (queryParams.method === 'GET' || !queryParams.method) {
            if (queryParams.select) {
                url.searchParams.append('select', queryParams.select);
            }
            if (queryParams.filter) {
                Object.entries(queryParams.filter).forEach(([key, value]) => {
                    url.searchParams.append(key, `eq.${value}`);
                });
            }
            if (queryParams.order) {
                queryParams.order.forEach(({ column, ascending }) => {
                    url.searchParams.append('order', `${column}.${ascending ? 'asc' : 'desc'}`);
                });
            }
            if (queryParams.limit) {
                url.searchParams.append('limit', queryParams.limit);
            }
        }
        
        const headers = this._getAuthHeaders();
        
        // For upsert operations, add resolution header
        if (queryParams.onConflict) {
            headers['Prefer'] = `resolution=merge-duplicates,return=representation`;
        }
        
        const response = await fetch(url.toString(), {
            method: queryParams.method || 'GET',
            headers: headers,
            body: queryParams.body ? JSON.stringify(queryParams.body) : undefined
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            let errorObj;
            try {
                errorObj = JSON.parse(errorText);
            } catch {
                errorObj = { message: errorText };
            }
            return { 
                data: null, 
                error: { 
                    message: errorObj.message || errorText, 
                    code: errorObj.code,
                    details: errorObj.details,
                    hint: errorObj.hint,
                    status: response.status 
                } 
            };
        }
        
        // Handle response body - read once
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            const text = await response.text();
            if (!text || text.trim() === '') {
                return { data: null, error: null };
            }
            try {
                const data = JSON.parse(text);
                return { data, error: null };
            } catch (e) {
                console.error('[DatabaseService] Failed to parse JSON response:', e);
                console.error('[DatabaseService] Response text:', text);
                return { data: null, error: { message: 'Invalid JSON response', status: response.status } };
            }
        }
        
        // Non-JSON response or empty
        return { data: null, error: null };
    },
    
    /**
     * Get the list of enabled example month keys from localStorage
     * @returns {Array<string>} Array of month keys that user has enabled
     */
    getEnabledExampleMonths() {
        try {
            const stored = localStorage.getItem('money_tracker_enabled_example_months');
            if (stored) {
                const enabled = JSON.parse(stored);
                return Array.isArray(enabled) ? enabled : [];
            }
            return [];
        } catch (error) {
            console.warn('[DatabaseService] Error reading enabled example months:', error);
            return [];
        }
    },
    
    /**
     * Set the list of enabled example month keys in localStorage
     * @param {Array<string>} monthKeys - Array of month keys to enable
     */
    setEnabledExampleMonths(monthKeys) {
        try {
            localStorage.setItem('money_tracker_enabled_example_months', JSON.stringify(monthKeys));
            console.log('[DatabaseService] Enabled example months updated:', monthKeys);
        } catch (error) {
            console.error('[DatabaseService] Error saving enabled example months:', error);
        }
    },
    
    /**
     * Add example month keys to the enabled list
     * @param {Array<string>} monthKeys - Month keys to add
     */
    addEnabledExampleMonths(monthKeys) {
        const current = this.getEnabledExampleMonths();
        const updated = [...new Set([...current, ...monthKeys])]; // Remove duplicates
        this.setEnabledExampleMonths(updated);
    },
    
    /**
     * Remove example month keys from the enabled list
     * @param {Array<string>} monthKeys - Month keys to remove (optional, if not provided removes all)
     */
    removeEnabledExampleMonths(monthKeys = null) {
        if (monthKeys === null) {
            // Remove all
            this.setEnabledExampleMonths([]);
        } else {
            const current = this.getEnabledExampleMonths();
            const updated = current.filter(key => !monthKeys.includes(key));
            this.setEnabledExampleMonths(updated);
        }
    },

    async getAllMonths(forceRefresh = false, includeExampleData = true) {
        try {
            console.log('[DatabaseService] getAllMonths() called, forceRefresh:', forceRefresh, 'includeExampleData:', includeExampleData);
            
            if (!this.client) {
                console.log('[DatabaseService] Client not initialized, initializing...');
                await this.initialize();
            }
            
            // Always fetch fresh from database - no caching
            console.log('[DatabaseService] Fetching months from database...');
            
            // Fetch user months using centralized query interface
            console.log('[DatabaseService] Querying user_months table...');
            
            // Get current user ID for filtering (validates session)
            const currentUserId = await this._getCurrentUserId();
            if (!currentUserId) {
                console.warn('[DatabaseService] No authenticated user - skipping user_months query');
                // Return empty array for user months, but still process example months if enabled
            } else {
                console.log(`[DatabaseService] Filtering user_months by user_id: ${currentUserId}`);
            }
            
            // First, do a diagnostic query to check if ANY data exists (just count)
            if (currentUserId) {
                try {
                    const diagnosticUrl = new URL(`${this.client.supabaseUrl}/rest/v1/user_months`);
                    diagnosticUrl.searchParams.append('select', 'id');
                    diagnosticUrl.searchParams.append('user_id', `eq.${currentUserId}`);
                    diagnosticUrl.searchParams.append('limit', '1');
                    
                    const diagnosticResponse = await fetch(diagnosticUrl.toString(), {
                        method: 'GET',
                        headers: this._getAuthHeaders()
                    });
                    
                    const diagnosticText = await diagnosticResponse.text();
                    const diagnosticData = diagnosticText ? JSON.parse(diagnosticText) : [];
                    console.log(`[DatabaseService] Diagnostic query: Status ${diagnosticResponse.status}, Found ${Array.isArray(diagnosticData) ? diagnosticData.length : 'unknown'} rows`);
                    console.log(`[DatabaseService] Diagnostic response headers:`, {
                        'content-range': diagnosticResponse.headers.get('content-range'),
                        'content-length': diagnosticResponse.headers.get('content-length')
                    });
                } catch (diagError) {
                    console.warn('[DatabaseService] Diagnostic query failed:', diagError);
                }
            }
            
            // Query user_months with user_id filter
            const userMonthsQueryOptions = {
                select: '*',
                order: [
                    { column: 'year', ascending: false },
                    { column: 'month', ascending: false }
                ]
            };
            
            if (currentUserId) {
                userMonthsQueryOptions.filter = { user_id: currentUserId };
            }
            
            const { data: userMonthsData, error: userMonthsError } = await this.querySelect(this._getTableName('userMonths'), userMonthsQueryOptions);
            
            if (userMonthsError) {
                console.error('[DatabaseService] Error fetching user_months:', userMonthsError);
                console.error('[DatabaseService] Error details:', {
                    message: userMonthsError.message,
                    code: userMonthsError.code,
                    status: userMonthsError.status
                });
                throw userMonthsError;
            }
            
            // Ensure userMonthsData is an array
            // Handle case where query returns null, undefined, or empty array
            let safeUserMonthsData = [];
            if (userMonthsData !== null && userMonthsData !== undefined) {
                if (Array.isArray(userMonthsData)) {
                    safeUserMonthsData = userMonthsData;
                } else if (typeof userMonthsData === 'object') {
                    // Single object returned instead of array
                    safeUserMonthsData = [userMonthsData];
                }
            }
            
            console.log(`[DatabaseService] user_months query result: ${safeUserMonthsData.length} months found`);
            console.log('[DatabaseService] Raw userMonthsData type:', typeof userMonthsData, Array.isArray(userMonthsData) ? 'array' : 'not array');
            console.log('[DatabaseService] Raw userMonthsData value:', userMonthsData);
            console.log('[DatabaseService] safeUserMonthsData length:', safeUserMonthsData.length);
            if (safeUserMonthsData.length > 0) {
                console.log('[DatabaseService] First month in safeUserMonthsData:', safeUserMonthsData[0]);
            }
            
            if (safeUserMonthsData.length > 0) {
                console.log('[DatabaseService] user_months data:', safeUserMonthsData.map(m => `${m.year}-${String(m.month).padStart(2, '0')}`));
            } else {
                if (currentUserId) {
                    console.warn('[DatabaseService] No user months found in database. If you just imported data, try refreshing the page.');
                    // Always retry once if no data found (helps with timing issues after import)
                    console.log('[DatabaseService] No data found - waiting 500ms and retrying query...');
                    await new Promise(resolve => setTimeout(resolve, 500));
                    const retryQueryOptions = {
                        select: '*',
                        order: [
                            { column: 'year', ascending: false },
                            { column: 'month', ascending: false }
                        ],
                        filter: { user_id: currentUserId }
                    };
                    const retryResult = await this.querySelect(this._getTableName('userMonths'), retryQueryOptions);
                    if (!retryResult.error && retryResult.data) {
                        const retryData = Array.isArray(retryResult.data) ? retryResult.data : (retryResult.data ? [retryResult.data] : []);
                        if (retryData.length > 0) {
                            console.log(`[DatabaseService] Retry successful: found ${retryData.length} months`);
                            safeUserMonthsData = retryData;
                        } else {
                            console.warn('[DatabaseService] Retry also returned empty array - data may not be committed yet or RLS policy may be blocking');
                        }
                    } else if (retryResult.error) {
                        console.error('[DatabaseService] Retry query failed:', retryResult.error);
                    }
                }
            }
            
            // Fetch example months only if requested AND user has enabled them
            let exampleMonthsData = [];
            const enabledExampleMonths = this.getEnabledExampleMonths();
            console.log('[DatabaseService] Enabled example months from localStorage:', enabledExampleMonths);
            
            if (includeExampleData && enabledExampleMonths.length > 0) {
                console.log('[DatabaseService] Querying example_months table for enabled months...');
                const { data: exampleData, error: exampleMonthsError } = await this.querySelect(this._getTableName('exampleMonths'), {
                    select: '*',
                    order: [
                        { column: 'year', ascending: false },
                        { column: 'month', ascending: false }
                    ]
                });
                
                if (exampleMonthsError) {
                    // If table doesn't exist yet, log warning but don't fail
                    if (exampleMonthsError.message && exampleMonthsError.message.includes('relation') && exampleMonthsError.message.includes('does not exist')) {
                        console.warn('[DatabaseService] example_months table does not exist yet. Run 01-schema-fresh-install.sql to create it.');
                        exampleMonthsData = [];
                    } else {
                        console.error('[DatabaseService] Error fetching example_months:', exampleMonthsError);
                        // Don't throw - just log and continue with empty array
                        exampleMonthsData = [];
                    }
                } else {
                    // Filter to only include enabled example months
                    const allExampleData = exampleData || [];
                    exampleMonthsData = allExampleData.filter(monthRecord => {
                        const monthKey = this.generateMonthKey(monthRecord.year, monthRecord.month);
                        return enabledExampleMonths.includes(monthKey);
                    });
                    console.log(`[DatabaseService] example_months query result: ${allExampleData.length} total, ${exampleMonthsData.length} enabled`);
                    if (exampleMonthsData.length > 0) {
                        console.log('[DatabaseService] Enabled example_months data:', exampleMonthsData.map(m => `${m.year}-${String(m.month).padStart(2, '0')}`));
                    }
                }
            } else {
                if (!includeExampleData) {
                    console.log('[DatabaseService] Skipping example_months query (includeExampleData=false)');
                } else {
                    console.log('[DatabaseService] Skipping example_months query (no enabled example months)');
                }
            }
            
            const monthsObject = {};
            
            // Add user months (always include user months, regardless of example data settings)
            if (safeUserMonthsData.length > 0) {
                console.log(`[DatabaseService] Processing ${safeUserMonthsData.length} user months...`);
                safeUserMonthsData.forEach(monthRecord => {
                    try {
                        const monthKey = this.generateMonthKey(monthRecord.year, monthRecord.month);
                        monthsObject[monthKey] = this.transformMonthFromDatabase(monthRecord);
                        console.log(`[DatabaseService] Added user month: ${monthKey}`);
                    } catch (error) {
                        console.error(`[DatabaseService] Error processing user month ${monthRecord.year}-${monthRecord.month}:`, error);
                    }
                });
            } else {
                console.warn('[DatabaseService] No user months to process');
            }
            
            // Add enabled example months only (they will override user months if same key exists, which shouldn't happen)
            if (includeExampleData && Array.isArray(exampleMonthsData) && exampleMonthsData.length > 0) {
                console.log(`[DatabaseService] Processing ${exampleMonthsData.length} enabled example months...`);
                exampleMonthsData.forEach(monthRecord => {
                    const monthKey = this.generateMonthKey(monthRecord.year, monthRecord.month);
                    monthsObject[monthKey] = this.transformMonthFromDatabase(monthRecord);
                });
            }
            
            // Add shared months
            if (currentUserId && window.DataSharingService) {
                try {
                    console.log('[DatabaseService] Fetching shared months...');
                    const sharedSharesResult = await this.getDataSharesSharedWithMe();
                    if (sharedSharesResult.success && sharedSharesResult.shares) {
                        for (const share of sharedSharesResult.shares) {
                            if (share.status !== 'accepted') {
                                console.log(`[DatabaseService] Skipping share ${share.id} - status: ${share.status}`);
                                continue;
                            }
                            
                            console.log(`[DatabaseService] Processing accepted share ${share.id} from owner ${share.owner_user_id}`, {
                                shareAllData: share.share_all_data,
                                sharedMonthsCount: share.shared_months?.length || 0
                            });
                            
                            // Fetch owner email once per share (more efficient)
                            let ownerEmail = 'Unknown User';
                            try {
                                const ownerEmailResult = await this.getUserEmailById(share.owner_user_id);
                                if (ownerEmailResult.success && ownerEmailResult.email) {
                                    ownerEmail = ownerEmailResult.email;
                                    console.log(`[DatabaseService] Owner email for share ${share.id}: ${ownerEmail}`);
                                }
                            } catch (emailError) {
                                console.warn('[DatabaseService] Error fetching owner email for share:', emailError);
                            }
                            
                            // If share_all_data is true, fetch all months from the owner
                            if (share.share_all_data) {
                                console.log(`[DatabaseService] Share ${share.id} has share_all_data=true, fetching all months from owner ${share.owner_user_id}`);
                                const ownerMonthsResult = await this.querySelect(this._getTableName('userMonths'), {
                                    select: '*',
                                    filter: { user_id: share.owner_user_id },
                                    order: [{ column: 'year', ascending: false }, { column: 'month', ascending: false }]
                                });
                                
                                if (ownerMonthsResult.data && ownerMonthsResult.data.length > 0) {
                                    console.log(`[DatabaseService] Found ${ownerMonthsResult.data.length} months from owner ${share.owner_user_id}`);
                                    for (const monthRecord of ownerMonthsResult.data) {
                                        const monthKey = this.generateMonthKey(monthRecord.year, monthRecord.month);
                                        if (!monthsObject[monthKey]) {
                                            const transformedMonth = this.transformMonthFromDatabase(monthRecord);
                                            transformedMonth.isShared = true;
                                            transformedMonth.sharedOwnerId = share.owner_user_id;
                                            transformedMonth.sharedAccessLevel = share.access_level;
                                            transformedMonth.sharedOwnerEmail = ownerEmail;
                                            
                                            monthsObject[monthKey] = transformedMonth;
                                            console.log(`[DatabaseService] Added shared month (all data): ${monthKey} from user ${share.owner_user_id} (${ownerEmail})`);
                                        }
                                    }
                                } else {
                                    console.log(`[DatabaseService] No months found for owner ${share.owner_user_id} (share_all_data=true)`);
                                }
                                continue; // Skip the shared_months loop since we've already loaded all months
                            }
                            
                            // Otherwise, process only the specified months
                            const sharedMonths = share.shared_months || [];
                            console.log(`[DatabaseService] Processing ${sharedMonths.length} specific months for share ${share.id}`);
                            for (const monthEntry of sharedMonths) {
                                let year, month;
                                
                                if (monthEntry.type === 'range') {
                                    const startYear = parseInt(monthEntry.startYear, 10);
                                    const endYear = parseInt(monthEntry.endYear, 10);
                                    const startMonth = parseInt(monthEntry.startMonth, 10);
                                    const endMonth = parseInt(monthEntry.endMonth, 10);
                                    
                                    for (let y = startYear; y <= endYear; y++) {
                                        const monthStart = (y === startYear) ? startMonth : 1;
                                        const monthEnd = (y === endYear) ? endMonth : 12;
                                        for (let m = monthStart; m <= monthEnd; m++) {
                                            year = y;
                                            month = m;
                                            const monthKey = this.generateMonthKey(year, month);
                                            if (!monthsObject[monthKey]) {
                                                const sharedMonthResult = await this.querySelect(this._getTableName('userMonths'), {
                                                    select: '*',
                                                    filter: {
                                                        user_id: share.owner_user_id,
                                                        year: year,
                                                        month: month
                                                    },
                                                    limit: 1
                                                });
                                                
                                                if (sharedMonthResult.data && sharedMonthResult.data.length > 0) {
                                                    const monthRecord = sharedMonthResult.data[0];
                                                    const transformedMonth = this.transformMonthFromDatabase(monthRecord);
                                                    transformedMonth.isShared = true;
                                                    transformedMonth.sharedOwnerId = share.owner_user_id;
                                                    transformedMonth.sharedAccessLevel = share.access_level;
                                                    transformedMonth.sharedOwnerEmail = ownerEmail; // Use pre-fetched email
                                                    
                                                    monthsObject[monthKey] = transformedMonth;
                                                    console.log(`[DatabaseService] Added shared month: ${monthKey} from user ${share.owner_user_id} (${ownerEmail})`);
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    year = parseInt(monthEntry.year, 10);
                                    month = parseInt(monthEntry.month, 10);
                                    const monthKey = this.generateMonthKey(year, month);
                                    if (!monthsObject[monthKey]) {
                                        const sharedMonthResult = await this.querySelect(this._getTableName('userMonths'), {
                                            select: '*',
                                            filter: {
                                                user_id: share.owner_user_id,
                                                year: year,
                                                month: month
                                            },
                                            limit: 1
                                        });
                                        
                                        if (sharedMonthResult.data && sharedMonthResult.data.length > 0) {
                                            const monthRecord = sharedMonthResult.data[0];
                                            const transformedMonth = this.transformMonthFromDatabase(monthRecord);
                                            transformedMonth.isShared = true;
                                            transformedMonth.sharedOwnerId = share.owner_user_id;
                                            transformedMonth.sharedAccessLevel = share.access_level;
                                            transformedMonth.sharedOwnerEmail = ownerEmail; // Use pre-fetched email
                                            
                                            monthsObject[monthKey] = transformedMonth;
                                            console.log(`[DatabaseService] Added shared month: ${monthKey} from user ${share.owner_user_id} (${ownerEmail})`);
                                        }
                                    }
                                }
                            }
                        }
                    }
                } catch (sharedError) {
                    console.warn('[DatabaseService] Error fetching shared months:', sharedError);
                }
            }
            
            console.log(`[DatabaseService] getAllMonths() completed. Total months: ${Object.keys(monthsObject).length}`);
            console.log('[DatabaseService] Month keys:', Object.keys(monthsObject));
            
            // Update in-memory cache for current session only (not persisted)
            this.monthsCache = monthsObject;
            this.cacheTimestamp = Date.now();
            
            // Don't save to localStorage - always fetch fresh from database
            // Only save cache to storage for example data clearing functionality
            // User data is always loaded fresh from user_months table
            
            return monthsObject;
        } catch (error) {
            console.error('[DatabaseService] Error getting all months:', error);
            console.error('[DatabaseService] Error details:', {
                message: error.message,
                code: error.code,
                details: error.details,
                hint: error.hint
            });
            
            // If database fetch fails, try to use cache as fallback
            if (this.monthsCache) {
                console.warn('[DatabaseService] Database fetch failed, using cached data as fallback');
                return { ...this.monthsCache };
            }
            
            throw error;
        }
    },
    
    /**
     * Get a specific month by monthKey (always fetches fresh from database)
     * @param {string} monthKey - Month key (e.g., "2025-11")
     * @param {boolean} forceRefresh - Deprecated, always fetches fresh
     * @returns {Promise<Object|null>} Month data or null
     */
    async getMonth(monthKey, forceRefresh = false) {
        try {
            console.log(`[DatabaseService] getMonth() called for: ${monthKey}`);
            
            if (!monthKey) {
                throw new Error('Month key is required');
            }
            
            if (!this.client) {
                console.log('[DatabaseService] Client not initialized, initializing...');
                await this.initialize();
            }
            
            // Always fetch fresh from database - check both tables using direct fetch
            const { year, month } = this.parseMonthKey(monthKey);
            console.log(`[DatabaseService] Parsed monthKey: year=${year}, month=${month}`);
            
            // First check example_months using centralized query interface
            console.log(`[DatabaseService] Checking example_months for ${year}-${month}...`);
            let fetchResult = await this.querySelect(this._getTableName('exampleMonths'), {
                select: '*',
                filter: { year: year, month: month },
                limit: 1
            });
            
            let data = null;
            let error = null;
            
            // Check if we got data from example_months
            if (fetchResult.data && Array.isArray(fetchResult.data) && fetchResult.data.length > 0) {
                data = fetchResult.data[0];
                console.log(`[DatabaseService] Found month ${monthKey} in example_months table`);
            } else {
                // Not found in example_months (empty array or error), check user_months
                console.log(`[DatabaseService] Not found in example_months (empty or error), checking user_months...`);
                
                // Get current user ID for filtering (validates session)
                const currentUserId = await this._getCurrentUserId();
                if (!currentUserId) {
                    console.log(`[DatabaseService] No authenticated user - skipping user_months query`);
                    return null;
                }
                
                const userFetchFilter = { year: year, month: month, user_id: currentUserId };
                const userFetchResult = await this.querySelect(this._getTableName('userMonths'), {
                    select: '*',
                    filter: userFetchFilter,
                    limit: 1
                });
                
                if (userFetchResult.data && Array.isArray(userFetchResult.data) && userFetchResult.data.length > 0) {
                    data = userFetchResult.data[0];
                    console.log(`[DatabaseService] Found month ${monthKey} in user_months table`);
                } else if (userFetchResult.error && (userFetchResult.error.code === 'PGRST116' || userFetchResult.error.status === 404)) {
                    // Not found in user's own months, check shared months
                    console.log(`[DatabaseService] Month ${monthKey} not found in user's months, checking shared months...`);
                    if (window.DataSharingService) {
                        const sharedSharesResult = await this.getDataSharesSharedWithMe();
                        if (sharedSharesResult.success && sharedSharesResult.shares) {
                            for (const share of sharedSharesResult.shares) {
                                if (share.status !== 'accepted') {
                                    continue;
                                }
                                const sharedMonths = share.shared_months || [];
                                const isMonthShared = window.DataSharingService._isMonthInSharedList(year, month, sharedMonths);
                                if (isMonthShared) {
                                    const sharedMonthResult = await this.querySelect(this._getTableName('userMonths'), {
                                        select: '*',
                                        filter: {
                                            user_id: share.owner_user_id,
                                            year: year,
                                            month: month
                                        },
                                        limit: 1
                                    });
                                    
                                    if (sharedMonthResult.data && sharedMonthResult.data.length > 0) {
                                        data = sharedMonthResult.data[0];
                                        const transformedMonth = this.transformMonthFromDatabase(data);
                                        transformedMonth.isShared = true;
                                        transformedMonth.sharedOwnerId = share.owner_user_id;
                                        transformedMonth.sharedAccessLevel = share.access_level;
                                        console.log(`[DatabaseService] Found month ${monthKey} in shared months from user ${share.owner_user_id}`);
                                        return transformedMonth;
                                    }
                                }
                            }
                        }
                    }
                    console.log(`[DatabaseService] Month ${monthKey} not found in either table or shared months`);
                    return null;
                } else if (userFetchResult.error) {
                    console.error(`[DatabaseService] Error fetching from user_months:`, userFetchResult.error);
                    error = userFetchResult.error;
                } else if (!userFetchResult.data || (Array.isArray(userFetchResult.data) && userFetchResult.data.length === 0)) {
                    // Empty result from user_months too, check shared months
                    console.log(`[DatabaseService] Month ${monthKey} not found in user's months, checking shared months...`);
                    if (window.DataSharingService) {
                        const sharedSharesResult = await this.getDataSharesSharedWithMe();
                        if (sharedSharesResult.success && sharedSharesResult.shares) {
                            for (const share of sharedSharesResult.shares) {
                                if (share.status !== 'accepted') {
                                    continue;
                                }
                                const sharedMonths = share.shared_months || [];
                                const isMonthShared = window.DataSharingService._isMonthInSharedList(year, month, sharedMonths);
                                if (isMonthShared) {
                                    const sharedMonthResult = await this.querySelect(this._getTableName('userMonths'), {
                                        select: '*',
                                        filter: {
                                            user_id: share.owner_user_id,
                                            year: year,
                                            month: month
                                        },
                                        limit: 1
                                    });
                                    
                                    if (sharedMonthResult.data && sharedMonthResult.data.length > 0) {
                                        data = sharedMonthResult.data[0];
                                        const transformedMonth = this.transformMonthFromDatabase(data);
                                        transformedMonth.isShared = true;
                                        transformedMonth.sharedOwnerId = share.owner_user_id;
                                        transformedMonth.sharedAccessLevel = share.access_level;
                                        console.log(`[DatabaseService] Found month ${monthKey} in shared months from user ${share.owner_user_id}`);
                                        return transformedMonth;
                                    }
                                }
                            }
                        }
                    }
                    console.log(`[DatabaseService] Month ${monthKey} not found in either table or shared months (both returned empty)`);
                    return null;
                }
                
                // If we had an error from example_months but user_months worked, clear the error
                if (data && fetchResult.error) {
                    console.log(`[DatabaseService] Found in user_months despite example_months error, ignoring example_months error`);
                } else if (fetchResult.error && !data) {
                    // Both failed or both empty
                    console.error(`[DatabaseService] Error fetching from example_months:`, fetchResult.error);
                    error = fetchResult.error;
                }
            }
            
            if (error) {
                throw error;
            }
            
            const monthData = data ? this.transformMonthFromDatabase(data) : null;
            console.log(`[DatabaseService] getMonth() completed for ${monthKey}:`, monthData ? 'Found' : 'Not found');
            
            // No caching - always return fresh data from database
            return monthData;
        } catch (error) {
            console.error(`[DatabaseService] Error getting month ${monthKey}:`, error);
            console.error('[DatabaseService] Error details:', {
                message: error.message,
                code: error.code,
                details: error.details,
                hint: error.hint,
                status: error.status
            });
            
            // No fallback to cache - fail hard to ensure data accuracy
            throw error;
        }
    },
    
    /**
     * Save a month to database
     * @param {string} monthKey - Month key
     * @param {Object} monthData - Month data object
     * @param {boolean} forceUserTable - Force save to user_months table (for imports)
     * @returns {Promise<boolean>} Success status
     */
    async saveMonth(monthKey, monthData, forceUserTable = false) {
        try {
            console.log(`[DatabaseService] saveMonth() called for: ${monthKey}, forceUserTable: ${forceUserTable}`);
            
            if (!monthKey || !monthData) {
                throw new Error('Month key and data are required');
            }
            
            if (!this.client) {
                console.log('[DatabaseService] Client not initialized, initializing...');
                await this.initialize();
            }
            
            const { year, month } = this.parseMonthKey(monthKey);
            console.log(`[DatabaseService] Parsed monthKey: year=${year}, month=${month}`);
            
            // Determine which table to use
            // If forceUserTable is true (for imports), always use user_months
            // Otherwise, check if it's example data
            let tableName;
            if (forceUserTable) {
                tableName = this._getTableName('userMonths');
                console.log(`[DatabaseService] Using user_months table (forced for import)`);
            } else {
                tableName = await this.getTableName(monthKey);
                console.log(`[DatabaseService] Using ${tableName} table (determined from monthKey)`);
            }
            
            // Get user ID if saving to user_months table (validates session)
            let userId = null;
            if (tableName === this._getTableName('userMonths')) {
                userId = await this._getCurrentUserId();
                if (!userId) {
                    throw new Error('User not authenticated - cannot save to user_months without authentication');
                }
                console.log(`[DatabaseService] User ID for user_months: ${userId}`);

                // Check permission to create months (free tier limited to 2)
                if (window.PermissionService) {
                    // Check if this month already exists (updating vs creating)
                    const existingMonth = await this.getMonth(monthKey);
                    const isNewMonth = !existingMonth;

                    if (isNewMonth) {
                        // Count existing user months
                        const monthCount = await this.getUserMonthCount(userId);
                        console.log(`[DatabaseService] User has ${monthCount} months, checking permission...`);

                        const limitCheck = await window.PermissionService.hasReachedLimit('months.create', monthCount);
                        if (limitCheck.reachedLimit) {
                            console.warn(`[DatabaseService] Month limit reached: ${limitCheck.reason}`);
                            throw new Error(`Month limit reached: Free plan allows ${limitCheck.limit} months. Upgrade to Premium for unlimited months.`);
                        }
                    }
                }

                // Check if this is shared data - if so, verify write permission
                if (monthData.isShared && monthData.sharedOwnerId && monthData.sharedOwnerId !== userId) {
                    if (!window.DataSharingService) {
                        throw new Error('Cannot save shared data - DataSharingService not available');
                    }
                    const canWrite = await window.DataSharingService.canWrite(
                        monthData.sharedOwnerId,
                        'month',
                        monthKey,
                        { year: year, month: month }
                    );
                    if (!canWrite) {
                        throw new Error('You do not have write permission for this shared month');
                    }
                    // For shared data, we need to save to the owner's user_id
                    userId = monthData.sharedOwnerId;
                    console.log(`[DatabaseService] Saving shared month - using owner user_id: ${userId}`);
                }
            }
            
            const monthRecord = this.transformMonthToDatabase(monthData, year, month, userId);
            console.log(`[DatabaseService] Transformed month record:`, {
                year: monthRecord.year,
                month: monthRecord.month,
                month_name: monthRecord.month_name,
                user_id: monthRecord.user_id || 'N/A (example_months)'
            });
            
            console.log(`[DatabaseService] Upserting to ${tableName} table...`);
            
            // Use centralized upsert method
            // For user_months, include user_id in filter to ensure we update the correct user's record
            const upsertOptions = { filter: { year, month } };
            if (tableName === this._getTableName('userMonths') && userId) {
                upsertOptions.filter.user_id = userId;
            }
            
            const upsertResult = await this.queryUpsert(tableName, monthRecord, upsertOptions);
            
            if (upsertResult.error) {
                console.error(`[DatabaseService] Error upserting to ${tableName}:`, upsertResult.error);
                console.error('[DatabaseService] Error details:', upsertResult.error);
                throw upsertResult.error;
            }
            
            console.log(`[DatabaseService] Successfully saved month ${monthKey} to ${tableName} table`);
            console.log(`[DatabaseService] Upsert result:`, {
                hasData: upsertResult.data !== null && upsertResult.data !== undefined,
                dataType: typeof upsertResult.data,
                isArray: Array.isArray(upsertResult.data),
                dataValue: upsertResult.data
            });
            
            if (upsertResult.data) {
                const upsertData = Array.isArray(upsertResult.data) ? upsertResult.data : [upsertResult.data];
                if (upsertData.length > 0) {
                    console.log(`[DatabaseService] Upsert returned data:`, upsertData[0]);
                    console.log(`[DatabaseService] Upsert returned record ID:`, upsertData[0].id);
                    console.log(`[DatabaseService] Upsert returned year/month:`, upsertData[0].year, upsertData[0].month);
                    
                    // Verify the data can be read back immediately
                    console.log(`[DatabaseService] Verifying saved data can be read back...`);
                    const verifyResult = await this.querySelect(tableName, {
                        select: '*',
                        filter: { year: year, month: month },
                        limit: 1
                    });
                    if (verifyResult.data && Array.isArray(verifyResult.data) && verifyResult.data.length > 0) {
                        console.log(`[DatabaseService] ✓ Verification successful - data can be read back`);
                    } else {
                        console.error(`[DatabaseService] ✗ Verification failed - data cannot be read back (RLS policy issue?)`);
                        console.error(`[DatabaseService] Verify result:`, verifyResult);
                    }
                } else {
                    console.warn(`[DatabaseService] Upsert succeeded but returned empty array`);
                }
            } else {
                console.warn(`[DatabaseService] Upsert succeeded but upsertResult.data is null/undefined`);
            }
            
            // Small delay to ensure Supabase commit completes before next query
            // This helps with timing issues where queries happen immediately after save
            await new Promise(resolve => setTimeout(resolve, 300));
            
            // Clear cache to ensure next fetch gets fresh data
            if (this.monthsCache && this.monthsCache[monthKey]) {
                delete this.monthsCache[monthKey];
            }
            
            // Don't save to localStorage - data is in database, will be loaded fresh on next page load
            // User data is always saved to user_months table and loaded fresh
            
            return true;
        } catch (error) {
            console.error(`[DatabaseService] Error saving month ${monthKey}:`, error);
            console.error('[DatabaseService] Error details:', {
                message: error.message,
                code: error.code,
                details: error.details,
                hint: error.hint
            });
            throw error;
        }
    },
    
    /**
     * Delete a month from database
     * @param {string} monthKey - Month key
     * @returns {Promise<boolean>} Success status
     * @throws {Error} If attempting to delete example data
     */
    async deleteMonth(monthKey) {
        try {
            console.log(`[DatabaseService] deleteMonth() called for: ${monthKey}`);
            
            if (!monthKey) {
                throw new Error('Month key is required');
            }
            
            if (!this.client) {
                console.log('[DatabaseService] Client not initialized, initializing...');
                await this.initialize();
            }
            
            // Protect example data from deletion
            console.log(`[DatabaseService] Checking if ${monthKey} is example data...`);
            const isExample = await this.isExampleData(monthKey);
            if (isExample) {
                console.log(`[DatabaseService] ${monthKey} is example data - deletion blocked`);
                throw new Error('Example data cannot be deleted. This data is protected.');
            }
            
            const { year, month } = this.parseMonthKey(monthKey);
            console.log(`[DatabaseService] Parsed monthKey: year=${year}, month=${month}`);
            
            // Get user ID for user_months deletion (validates session)
            const userId = await this._getCurrentUserId();
            if (!userId) {
                throw new Error('User not authenticated - cannot delete from user_months without authentication');
            }
            console.log(`[DatabaseService] User ID for deletion: ${userId}`);
            
            // Check if this is shared data - if so, verify delete permission
            const monthData = await this.getMonth(monthKey);
            if (monthData && monthData.isShared && monthData.sharedOwnerId && monthData.sharedOwnerId !== userId) {
                if (!window.DataSharingService) {
                    throw new Error('Cannot delete shared data - DataSharingService not available');
                }
                const canDelete = await window.DataSharingService.canDelete(
                    monthData.sharedOwnerId,
                    'month',
                    monthKey,
                    { year: year, month: month }
                );
                if (!canDelete) {
                    throw new Error('You do not have delete permission for this shared month');
                }
                // For shared data deletion, we need to delete from owner's data
                const ownerUserId = monthData.sharedOwnerId;
                console.log(`[DatabaseService] Deleting shared month - using owner user_id: ${ownerUserId}`);
                const deleteResult = await this.queryDelete(this._getTableName('userMonths'), { year, month, user_id: ownerUserId });
                if (deleteResult.error) {
                    throw deleteResult.error;
                }
                return true;
            }
            
            // Only delete from user_months (never from example_months) using centralized query interface
            // Include user_id in filter to ensure we only delete the current user's records
            console.log(`[DatabaseService] Deleting from user_months table...`);
            
            const deleteResult = await this.queryDelete(this._getTableName('userMonths'), { year, month, user_id: userId });
            
            if (deleteResult.error) {
                console.error(`[DatabaseService] Error deleting from user_months:`, deleteResult.error);
                console.error('[DatabaseService] Error details:', deleteResult.error);
                throw deleteResult.error;
            }
            
            console.log(`[DatabaseService] Successfully deleted month ${monthKey} from user_months`);
            if (deleteResult.data) {
                const deletedData = Array.isArray(deleteResult.data) ? deleteResult.data : [deleteResult.data];
                if (deletedData.length > 0) {
                    console.log(`[DatabaseService] Delete returned data:`, deletedData);
                }
            }
            
            // Clear cache to ensure next fetch gets fresh data
            if (this.monthsCache && this.monthsCache[monthKey]) {
                delete this.monthsCache[monthKey];
                console.log(`[DatabaseService] Removed ${monthKey} from in-memory cache`);
            }
            
            // Don't save to localStorage - data is deleted from database, will be reflected on next page load
            
            return true;
        } catch (error) {
            console.error(`[DatabaseService] Error deleting month ${monthKey}:`, error);
            console.error('[DatabaseService] Error details:', {
                message: error.message,
                code: error.code,
                details: error.details,
                hint: error.hint
            });
            throw error;
        }
    },
    
    /**
     * Get all pots from database (including shared pots)
     * @returns {Promise<Object>} Pots data object
     */
    async getAllPots() {
        try {
            if (!this.client) {
                await this.initialize();
            }
            
            const currentUserId = await this._getCurrentUserId();
            if (!currentUserId) {
                return {};
            }
            
            const result = await this.querySelect('pots', {
                select: '*',
                filter: { user_id: currentUserId },
                order: [{ column: 'created_at', ascending: false }]
            });
            
            if (result.error) {
                throw result.error;
            }
            
            const potsObject = {};
            const potsData = result.data || [];
            if (Array.isArray(potsData)) {
                potsData.forEach(pot => {
                    potsObject[pot.id] = this.transformPotFromDatabase(pot);
                });
            }
            
            // Add shared pots
            if (window.DataSharingService) {
                try {
                    const sharedSharesResult = await this.getDataSharesSharedWithMe();
                    if (sharedSharesResult.success && sharedSharesResult.shares) {
                        for (const share of sharedSharesResult.shares) {
                            if (share.status !== 'accepted') {
                                continue;
                            }
                            if (share.shared_pots || share.share_all_data) {
                                const sharedPotsResult = await this.querySelect('pots', {
                                    select: '*',
                                    filter: { user_id: share.owner_user_id },
                                    order: [{ column: 'created_at', ascending: false }]
                                });
                                
                                if (sharedPotsResult.data && Array.isArray(sharedPotsResult.data)) {
                                    sharedPotsResult.data.forEach(pot => {
                                        const transformedPot = this.transformPotFromDatabase(pot);
                                        transformedPot.isShared = true;
                                        transformedPot.sharedOwnerId = share.owner_user_id;
                                        transformedPot.sharedAccessLevel = share.access_level;
                                        potsObject[`shared_${share.owner_user_id}_${pot.id}`] = transformedPot;
                                    });
                                }
                            }
                        }
                    }
                } catch (sharedError) {
                    console.warn('[DatabaseService] Error fetching shared pots:', sharedError);
                }
            }
            
            return potsObject;
        } catch (error) {
            console.error('Error getting all pots:', error);
            throw error;
        }
    },
    
    /**
     * Save all pots to database
     * @param {Object} potsData - Pots data object
     * @returns {Promise<boolean>} Success status
     */
    async saveAllPots(potsData) {
        try {
            if (!this.client) {
                await this.initialize();
            }
            
            if (!potsData || typeof potsData !== 'object') {
                throw new Error('Pots data must be an object');
            }
            
            const potsArray = Object.values(potsData);
            
            if (potsArray.length === 0) {
                return true;
            }
            
            const potsRecords = potsArray.map(pot => this.transformPotToDatabase(pot));
            
            console.log('[DatabaseService] Upserting pots...');
            // For pots, we'll do a simple POST (no conflict resolution needed for now)
            const upsertResult = await this.queryUpsert('pots', potsRecords);
            
            if (upsertResult.error) {
                console.error('[DatabaseService] Error saving pots:', upsertResult.error);
                throw upsertResult.error;
            }
            
            console.log('[DatabaseService] Successfully saved pots');
            return true;
        } catch (error) {
            console.error('Error saving pots:', error);
            throw error;
        }
    },
    
    /**
     * Get settings from database
     * Uses caching to prevent excessive database calls
     * Handles concurrent requests by reusing the same promise
     * @returns {Promise<Object|null>} Settings object or null
     */
    async getSettings() {
        try {
            if (!this.client) {
                console.log('[DatabaseService] Client not initialized, initializing...');
                await this.initialize();
            }
            
            // Get current user ID for filtering (validates session)
            const currentUserId = await this._getCurrentUserId();
            if (!currentUserId) {
                console.warn('[DatabaseService] No authenticated user - cannot fetch settings');
                return null;
            }
            
            // Check cache first - return cached settings if available for this user
            if (this.settingsCache && this.settingsCacheUserId === currentUserId) {
                console.log('[DatabaseService] getSettings() returning cached settings');
                return this.settingsCache;
            }
            
            // If there's already a pending request for this user, return that promise
            if (this.settingsCachePromise && this.settingsCacheUserId === currentUserId) {
                console.log('[DatabaseService] getSettings() reusing pending request');
                return await this.settingsCachePromise;
            }
            
            console.log('[DatabaseService] getSettings() called - fetching from database');
            const startTime = Date.now();
            
            // Create a promise for this request and cache it to handle concurrent calls
            this.settingsCacheUserId = currentUserId;
            this.settingsCachePromise = (async () => {
                try {
                    console.log('[DatabaseService] Querying settings table for user_id:', currentUserId);
                    
                    // Use centralized query interface for settings
                    const queryResult = await Promise.race([
                        this.querySelect(this._getTableName('settings'), {
                            select: '*',
                            filter: { user_id: currentUserId },
                            limit: 1
                        }),
                        new Promise((_, reject) => setTimeout(() => reject(new Error('Settings fetch timeout')), 5000))
                    ]).catch(err => {
                        console.error('[DatabaseService] Settings query failed:', err);
                        return { data: null, error: err };
                    });
                    
                    const totalElapsed = Date.now() - startTime;
                    console.log(`[DatabaseService] Settings fetch completed in ${totalElapsed}ms`);
                    
                    // Convert direct fetch result to Supabase-like format
                    let queryResultFormatted;
                    if (queryResult.error) {
                        queryResultFormatted = { data: null, error: queryResult.error };
                    } else if (queryResult.data && Array.isArray(queryResult.data) && queryResult.data.length > 0) {
                        // Return single item (like .single() would)
                        queryResultFormatted = { data: queryResult.data[0], error: null };
                    } else if (queryResult.data && Array.isArray(queryResult.data) && queryResult.data.length === 0) {
                        // No data found
                        queryResultFormatted = { data: null, error: { code: 'PGRST116', message: 'No rows found' } };
                    } else {
                        queryResultFormatted = { data: queryResult.data, error: null };
                    }
                    
                    const { data, error } = queryResultFormatted;
                    
                    if (error) {
                        if (error.code === 'TIMEOUT') {
                            console.warn('[DatabaseService] Settings query timed out - returning null');
                            return null;
                        }
                        if (error.code === 'PGRST116') {
                            console.log('[DatabaseService] Settings not found (PGRST116) - returning null');
                            return null;
                        }
                        // Handle network/connection errors gracefully
                        if (error.message && error.message.includes('Load failed')) {
                            console.warn('[DatabaseService] Settings table may not exist or connection failed. Returning null.');
                            return null;
                        }
                        console.error('[DatabaseService] Error fetching settings:', error);
                        console.error('[DatabaseService] Error details:', {
                            message: error.message,
                            code: error.code,
                            details: error.details,
                            hint: error.hint
                        });
                        // Return null instead of throwing to prevent blocking initialization
                        return null;
                    }
                    
                    console.log('[DatabaseService] Settings fetched successfully:', data ? 'Found' : 'Not found');
                    const settings = data ? this.transformSettingsFromDatabase(data) : null;
                    
                    // Cache the settings for this user
                    this.settingsCache = settings;
                    
                    if (settings) {
                        console.log('[DatabaseService] Settings data cached');
                    } else {
                        console.log('[DatabaseService] No settings data returned');
                    }
                    
                    return settings;
                } finally {
                    // Clear the promise cache after completion
                    this.settingsCachePromise = null;
                }
            })();
            
            return await this.settingsCachePromise;
        } catch (error) {
            // Clear promise cache on error
            this.settingsCachePromise = null;
            
            // Only log error once, don't spam console
            if (!this._settingsErrorLogged) {
                console.error('[DatabaseService] Error getting settings:', error);
                console.error('[DatabaseService] Error details:', {
                    message: error.message,
                    code: error.code,
                    details: error.details,
                    hint: error.hint
                });
                this._settingsErrorLogged = true;
            }
            // Return null instead of throwing to prevent cascading errors
            console.log('[DatabaseService] getSettings() returning null due to error');
            return null;
        }
    },
    
    /**
     * Save settings to database
     * @param {Object} settings - Settings object
     * @returns {Promise<boolean>} Success status
     */
    async saveSettings(settings) {
        try {
            console.log('[DatabaseService] saveSettings() called:', settings);
            
            if (!settings || typeof settings !== 'object') {
                throw new Error('Settings must be an object');
            }
            
            if (!this.client) {
                console.log('[DatabaseService] Client not initialized, initializing...');
                await this.initialize();
            }
            
            // Get current user ID (validates session)
            const currentUserId = await this._getCurrentUserId();
            if (!currentUserId) {
                throw new Error('User must be authenticated to save settings');
            }
            
            const settingsRecord = this.transformSettingsToDatabase(settings);
            settingsRecord.user_id = currentUserId;
            console.log('[DatabaseService] Transformed settings record:', settingsRecord);
            
            console.log('[DatabaseService] Upserting to settings table for user_id:', currentUserId);
            
            // Use centralized upsert method with user_id as identifier
            const upsertResult = await this.queryUpsert(this._getTableName('settings'), settingsRecord, {
                identifier: 'user_id',
                identifierValue: currentUserId
            });
            
            if (upsertResult.error) {
                console.error('[DatabaseService] Error saving settings:', upsertResult.error);
                console.error('[DatabaseService] Error details:', {
                    message: upsertResult.error.message,
                    code: upsertResult.error.code,
                    details: upsertResult.error.details,
                    hint: upsertResult.error.hint,
                    status: upsertResult.error.status
                });
                throw upsertResult.error;
            }
            
            console.log('[DatabaseService] Successfully saved settings');
            if (upsertResult.data) {
                console.log('[DatabaseService] Upsert returned data:', upsertResult.data);
            }
            
            // Invalidate settings cache after saving
            this.settingsCache = null;
            this.settingsCacheUserId = null;
            this.settingsCachePromise = null;
            console.log('[DatabaseService] Settings cache invalidated');
            
            return true;
        } catch (error) {
            console.error('[DatabaseService] Error saving settings:', error);
            console.error('[DatabaseService] Error details:', {
                message: error.message,
                code: error.code,
                details: error.details,
                hint: error.hint
            });
            throw error;
        }
    },
    
    /**
     * Transform month data from database format to application format
     * @param {Object} dbRecord - Database record
     * @returns {Object} Application format month data
     */
    transformMonthFromDatabase(dbRecord) {
        return {
            key: this.generateMonthKey(dbRecord.year, dbRecord.month),
            year: dbRecord.year,
            month: dbRecord.month,
            monthName: dbRecord.month_name || this.getMonthName(dbRecord.month),
            dateRange: dbRecord.date_range || {},
            weeklyBreakdown: dbRecord.weekly_breakdown || [],
            fixedCosts: dbRecord.fixed_costs || [],
            variableCosts: dbRecord.variable_costs || [],
            unplannedExpenses: dbRecord.unplanned_expenses || [],
            incomeSources: dbRecord.income_sources || [],
            pots: dbRecord.pots || [],
            createdAt: dbRecord.created_at,
            updatedAt: dbRecord.updated_at
        };
    },
    
    /**
     * Transform month data from application format to database format
     * @param {Object} monthData - Application format month data
     * @param {number} year - Year
     * @param {number} month - Month
     * @returns {Object} Database format record
     */
    transformMonthToDatabase(monthData, year, month, userId = null) {
        const now = new Date().toISOString();
        
        const record = {
            year: year,
            month: month,
            month_name: monthData.monthName || this.getMonthName(month),
            date_range: monthData.dateRange || {},
            weekly_breakdown: monthData.weeklyBreakdown || [],
            fixed_costs: monthData.fixedCosts || [],
            variable_costs: monthData.variableCosts || [],
            unplanned_expenses: monthData.unplannedExpenses || [],
            income_sources: monthData.incomeSources || [],
            pots: monthData.pots || [],
            updated_at: now,
            created_at: monthData.createdAt || now
        };
        
        // Include user_id only for user_months table
        if (userId !== null) {
            record.user_id = userId;
        }
        
        return record;
    },
    
    /**
     * Transform pot data from database format to application format
     * @param {Object} dbRecord - Database record
     * @returns {Object} Application format pot data
     */
    transformPotFromDatabase(dbRecord) {
        return {
            id: dbRecord.id,
            name: dbRecord.name,
            estimatedAmount: dbRecord.estimated_amount || 0,
            actualAmount: dbRecord.actual_amount || 0,
            comments: dbRecord.comments || '',
            createdAt: dbRecord.created_at,
            updatedAt: dbRecord.updated_at
        };
    },
    
    /**
     * Transform pot data from application format to database format
     * @param {Object} potData - Application format pot data
     * @returns {Object} Database format record
     */
    transformPotToDatabase(potData) {
        const now = new Date().toISOString();
        
        return {
            id: potData.id || undefined,
            name: potData.name || '',
            estimated_amount: potData.estimatedAmount || 0,
            actual_amount: potData.actualAmount || 0,
            comments: potData.comments || '',
            updated_at: now,
            created_at: potData.createdAt || now
        };
    },
    
    /**
     * Transform settings from database format to application format
     * @param {Object} dbRecord - Database record
     * @returns {Object} Application format settings
     */
    transformSettingsFromDatabase(dbRecord) {
        return {
            currency: dbRecord.currency || '£',
            fontScale: dbRecord.font_size || 'medium',
            defaultFixedCosts: dbRecord.default_fixed_costs || [],
            defaultVariableCategories: dbRecord.default_variable_categories || ['Food', 'Travel/Transport', 'Activities'],
            defaultPots: dbRecord.default_pots || []
        };
    },
    
    /**
     * Transform settings from application format to database format
     * @param {Object} settings - Application format settings
     * @returns {Object} Database format record
     */
    transformSettingsToDatabase(settings) {
        return {
            currency: settings.currency || '£',
            font_size: settings.fontScale || 'medium',
            default_fixed_costs: settings.defaultFixedCosts || [],
            default_variable_categories: settings.defaultVariableCategories || ['Food', 'Travel/Transport', 'Activities'],
            default_pots: settings.defaultPots || []
        };
    },
    
    /**
     * Generate month key from year and month
     * @param {number} year - Year
     * @param {number} month - Month (1-12)
     * @returns {string} Month key
     */
    generateMonthKey(year, month) {
        return `${year}-${String(month).padStart(2, '0')}`;
    },
    
    /**
     * Parse month key to year and month
     * Handles both formats: "2026-01" (year-month) and "january-2026" (monthname-year)
     * @param {string} monthKey - Month key
     * @returns {Object} Object with year and month
     */
    parseMonthKey(monthKey) {
        if (!monthKey || typeof monthKey !== 'string') {
            throw new Error('Invalid month key');
        }
        
        const parts = monthKey.split('-');
        if (parts.length !== 2) {
            throw new Error('Invalid month key format');
        }
        
        // Check if first part is a month name (text) or year (number)
        const firstPart = parts[0].toLowerCase();
        const secondPart = parts[1].toLowerCase();
        
        // Month names for conversion
        const monthNames = [
            'january', 'february', 'march', 'april', 'may', 'june',
            'july', 'august', 'september', 'october', 'november', 'december'
        ];
        
        let year, month;
        
        // Check if format is "monthname-year" (e.g., "january-2026")
        if (monthNames.includes(firstPart)) {
            month = monthNames.indexOf(firstPart) + 1; // Convert to 1-12
            year = parseInt(secondPart, 10);
            if (isNaN(year)) {
                throw new Error(`Invalid year in month key: ${monthKey}`);
            }
        }
        // Check if format is "year-month" (e.g., "2026-01")
        else {
            year = parseInt(firstPart, 10);
            month = parseInt(secondPart, 10);
            if (isNaN(year) || isNaN(month)) {
                throw new Error(`Invalid year or month in month key: ${monthKey}`);
            }
        }
        
        // Validate month is 1-12
        if (month < 1 || month > 12) {
            throw new Error(`Invalid month number: ${month} (must be 1-12)`);
        }
        
        return { year, month };
    },
    
    /**
     * Get month name from month number
     * @param {number} monthNumber - Month number (1-12)
     * @returns {string} Month name
     */
    getMonthName(monthNumber) {
        const monthNames = [
            'January', 'February', 'March', 'April', 'May', 'June',
            'July', 'August', 'September', 'October', 'November', 'December'
        ];
        if (monthNumber < 1 || monthNumber > 12) {
            throw new Error('Invalid month number');
        }
        return monthNames[monthNumber - 1] || '';
    },
    
    /**
     * Clear all user data from database tables
     * Deletes all data from user_months and pots tables for the current user only
     * Does NOT delete example_months, settings, or other users' data
     * Does NOT delete tables themselves
     * @returns {Promise<Object>} Result object with success status and counts
     */
    async clearAllUserTables() {
        try {
            console.log('[DatabaseService] clearAllUserTables() called');
            
            if (!this.client) {
                console.log('[DatabaseService] Client not initialized, initializing...');
                await this.initialize();
            }
            
            // Get current user ID - required to filter deletions to only current user's data (validates session)
            const currentUserId = await this._getCurrentUserId();
            if (!currentUserId) {
                throw new Error('User not authenticated - cannot delete user data without authentication');
            }
            console.log(`[DatabaseService] Clearing data for user_id: ${currentUserId}`);
            
            const result = {
                userMonthsDeleted: 0,
                potsDeleted: 0,
                success: false,
                errors: []
            };
            
            // Delete all user months for current user only using centralized query interface
            console.log(`[DatabaseService] Deleting user_months for user_id: ${currentUserId}...`);
            try {
                // Use queryDelete with user_id filter to only delete current user's data
                const deleteResult = await this.queryDelete(this._getTableName('userMonths'), { user_id: currentUserId });
                
                if (deleteResult.error) {
                    throw deleteResult.error;
                }
                
                const deletedMonths = deleteResult.data;
                result.userMonthsDeleted = deletedMonths ? (Array.isArray(deletedMonths) ? deletedMonths.length : 1) : 0;
                console.log(`[DatabaseService] Deleted ${result.userMonthsDeleted} user months for current user`);
            } catch (monthsError) {
                console.error('[DatabaseService] Exception deleting user_months:', monthsError);
                result.errors.push(`user_months: ${monthsError.message}`);
            }
            
            // Delete all pots for current user only using centralized query interface
            console.log(`[DatabaseService] Deleting pots for user_id: ${currentUserId}...`);
            try {
                // Use queryDelete with user_id filter to only delete current user's data
                const deleteResult = await this.queryDelete('pots', { user_id: currentUserId });
                
                if (deleteResult.error) {
                    throw deleteResult.error;
                }
                
                const deletedPots = deleteResult.data;
                result.potsDeleted = deletedPots ? (Array.isArray(deletedPots) ? deletedPots.length : 1) : 0;
                console.log(`[DatabaseService] Deleted ${result.potsDeleted} pots for current user`);
            } catch (potsError) {
                console.error('[DatabaseService] Exception deleting pots:', potsError);
                result.errors.push(`pots: ${potsError.message}`);
            }
            
            // Clear in-memory cache
            this.clearCache();
            console.log('[DatabaseService] Cleared in-memory cache');
            
            result.success = result.errors.length === 0;
            console.log('[DatabaseService] clearAllUserTables() completed:', result);
            
            return result;
        } catch (error) {
            console.error('[DatabaseService] Error clearing user tables:', error);
            throw error;
        }
    },
    
    /**
     * ============================================================================
     * DATA SHARING METHODS
     * ============================================================================
     */
    
    /**
     * Find user by email address
     * Note: This requires a Supabase Edge Function or admin API access
     * For now, this is a placeholder that will need to be implemented via Edge Function
     * @param {string} email - Email address to search for
     * @returns {Promise<{success: boolean, userId: string|null, error: string|null}>}
     */
    async findUserByEmail(email) {
        try {
            if (!email || typeof email !== 'string') {
                return {
                    success: false,
                    userId: null,
                    error: 'Email is required'
                };
            }
            
            if (!this.client || !this.client.supabaseUrl) {
                throw new Error('DatabaseService client not available');
            }
            
            const functionUrl = `${this.client.supabaseUrl}/functions/v1/user-lookup`;
            const authHeaders = this._getAuthHeaders();
            const edgeFunctionHeaders = {
                'apikey': authHeaders.apikey,
                'Authorization': authHeaders.Authorization,
                'Content-Type': 'application/json'
            };

            console.log('[DatabaseService] Calling user-lookup Edge Function (findByEmail):', { functionUrl, email });
            const response = await fetch(functionUrl, {
                method: 'POST',
                headers: edgeFunctionHeaders,
                body: JSON.stringify({ action: 'findByEmail', email: email })
            });

            console.log('[DatabaseService] user-lookup (findByEmail) response status:', response.status, response.statusText);
            
            if (!response.ok) {
                const errorText = await response.text();
                let errorData = {};
                try {
                    errorData = JSON.parse(errorText);
                } catch (e) {
                    errorData = { error: errorText || 'Failed to find user' };
                }
                console.error('[DatabaseService] user-lookup (findByEmail) error:', { status: response.status, errorData, errorText });
                
                if (response.status === 404) {
                    return {
                        success: false,
                        userId: null,
                        error: 'User not found. Please make sure the user has signed up for an account.'
                    };
                }
                
                return {
                    success: false,
                    userId: null,
                    error: errorData.error || errorData.message || `Failed to find user (HTTP ${response.status})`
                };
            }
            
            const data = await response.json();
            
            if (!data.userId) {
                return {
                    success: false,
                    userId: null,
                    error: 'User not found'
                };
            }
            
            return {
                success: true,
                userId: data.userId,
                error: null
            };
        } catch (error) {
            console.error('[DatabaseService] Exception finding user by email:', error);
            return {
                success: false,
                userId: null,
                error: error.message || 'An unexpected error occurred'
            };
        }
    },
    
    /**
     * Get user email by user ID
     * Note: This requires a Supabase Edge Function or admin API access
     * @param {string} userId - User ID to look up
     * @returns {Promise<{success: boolean, email: string|null, error: string|null}>}
     */
    async getUserEmailById(userId) {
        try {
            if (!userId || typeof userId !== 'string') {
                return {
                    success: false,
                    email: null,
                    error: 'User ID is required'
                };
            }
            
            if (!this.client || !this.client.supabaseUrl) {
                throw new Error('DatabaseService client not available');
            }
            
            const functionUrl = `${this.client.supabaseUrl}/functions/v1/user-lookup`;
            const authHeaders = this._getAuthHeaders();
            const edgeFunctionHeaders = {
                'apikey': authHeaders.apikey,
                'Authorization': authHeaders.Authorization,
                'Content-Type': 'application/json'
            };

            console.log('[DatabaseService] Calling user-lookup Edge Function (getEmailById):', { functionUrl, userId });
            const response = await fetch(functionUrl, {
                method: 'POST',
                headers: edgeFunctionHeaders,
                body: JSON.stringify({ action: 'getEmailById', userId: userId })
            });

            console.log('[DatabaseService] user-lookup (getEmailById) response status:', response.status, response.statusText);
            
            if (!response.ok) {
                const errorText = await response.text();
                let errorData = {};
                try {
                    errorData = JSON.parse(errorText);
                } catch (e) {
                    errorData = { error: errorText || 'Failed to get user email' };
                }
                console.error('[DatabaseService] user-lookup (getEmailById) error:', { status: response.status, errorData, errorText });

                if (response.status === 404) {
                    return {
                        success: false,
                        email: null,
                        error: 'User not found'
                    };
                }

                return {
                    success: false,
                    email: null,
                    error: errorData.error || errorData.message || `Failed to get user email (HTTP ${response.status})`
                };
            }
            
            const data = await response.json();
            
            if (!data.email) {
                return {
                    success: false,
                    email: null,
                    error: 'Email not found'
                };
            }
            
            return {
                success: true,
                email: data.email,
                error: null
            };
        } catch (error) {
            console.error('[DatabaseService] Exception getting user email by ID:', error);
            return {
                success: false,
                email: null,
                error: error.message || 'An unexpected error occurred'
            };
        }
    },
    
    /**
     * Create a data share
     * @param {string} sharedWithEmail - Email of user to share with
     * @param {string} accessLevel - Access level: 'read', 'read_write', or 'read_write_delete'
     * @param {Array} sharedMonths - Array of month objects or date ranges
     * @param {boolean} sharedPots - Whether to share pots
     * @param {boolean} sharedSettings - Whether to share settings
     * @param {boolean} shareAllData - Whether to share all data (optional, defaults to false)
     * @returns {Promise<{success: boolean, share: Object|null, error: string|null}>}
     */
    async createDataShare(sharedWithEmail, accessLevel, sharedMonths, sharedPots, sharedSettings, shareAllData = false) {
        console.log('[DatabaseService] createDataShare() called');
        console.log('[DatabaseService] Parameters:', { 
            sharedWithEmail, 
            accessLevel, 
            sharedMonthsCount: sharedMonths?.length || 0, 
            sharedPots, 
            sharedSettings 
        });
        
        try {
            const currentUserId = await this._getCurrentUserId();
            if (!currentUserId) {
                console.error('[DatabaseService] User not authenticated');
                return {
                    success: false,
                    share: null,
                    error: 'User not authenticated'
                };
            }
            
            console.log('[DatabaseService] Current user ID:', currentUserId);
            
            if (!window.SubscriptionGuard) {
                console.error('[DatabaseService] SubscriptionGuard not available');
                return {
                    success: false,
                    share: null,
                    error: 'SubscriptionGuard not available'
                };
            }
            
            const hasPremium = await window.SubscriptionGuard.hasTier('premium');
            console.log('[DatabaseService] Premium status:', hasPremium);
            
            if (!hasPremium) {
                return {
                    success: false,
                    share: null,
                    error: 'Premium subscription required to create shares'
                };
            }
            
            console.log('[DatabaseService] Looking up user by email:', sharedWithEmail);
            const userResult = await this.findUserByEmail(sharedWithEmail);
            console.log('[DatabaseService] findUserByEmail result:', userResult);
            
            if (!userResult.success || !userResult.userId) {
                return {
                    success: false,
                    share: null,
                    error: userResult.error || 'User not found'
                };
            }
            
            if (userResult.userId === currentUserId) {
                console.warn('[DatabaseService] Attempted to share with self');
                return {
                    success: false,
                    share: null,
                    error: 'Cannot share data with yourself'
                };
            }

            if (typeof window.DataSharingService !== 'undefined') {
                const blockedResult = await window.DataSharingService.checkIfBlocked(currentUserId, userResult.userId);
                if (blockedResult.isBlocked) {
                    console.warn('[DatabaseService] User is blocked');
                    return {
                        success: false,
                        share: null,
                        error: 'Cannot share data with this user - they have blocked you'
                    };
                }
            }

            let shareStatus = 'pending';
            let shouldCreateNotification = true;

            if (typeof window.NotificationPreferenceService !== 'undefined') {
                const preferencesResult = await window.NotificationPreferenceService.getPreferences(userResult.userId);
                if (preferencesResult.success && preferencesResult.preferences) {
                    const preferences = preferencesResult.preferences;
                    if (preferences.auto_accept_shares) {
                        shareStatus = 'accepted';
                        shouldCreateNotification = false;
                        console.log('[DatabaseService] Auto-accept enabled, setting status to accepted');
                    } else if (preferences.auto_decline_shares) {
                        shareStatus = 'declined';
                        shouldCreateNotification = false;
                        console.log('[DatabaseService] Auto-decline enabled, setting status to declined');
                    }
                }
            }
            
            const tableName = this._getTableName('dataShares');
            
            // Get or create conversation between owner and recipient for share requests
            let conversationId = null;
            if (typeof window.MessagingService !== 'undefined') {
                console.log('[DatabaseService] Getting or creating conversation for share request');
                const conversationResult = await window.MessagingService.getOrCreateConversation(currentUserId, userResult.userId);
                if (conversationResult.success && conversationResult.conversation) {
                    conversationId = conversationResult.conversation.id;
                    console.log('[DatabaseService] Conversation ID for share:', conversationId);
                } else {
                    console.warn('[DatabaseService] Failed to get/create conversation:', conversationResult.error);
                    // Continue without conversation_id - share can still be created
                }
            } else {
                console.warn('[DatabaseService] MessagingService not available, cannot link share to conversation');
            }
            
            // Check if a share already exists for this owner-user pair
            console.log('[DatabaseService] Checking for existing share between owner:', currentUserId, 'and user:', userResult.userId);
            const existingShareResult = await this.querySelect(tableName, {
                filter: {
                    owner_user_id: currentUserId,
                    shared_with_user_id: userResult.userId
                },
                limit: 1
            });
            
            let share;
            
            if (existingShareResult.data && existingShareResult.data.length > 0) {
                // Share already exists, update it
                console.log('[DatabaseService] Existing share found, updating share ID:', existingShareResult.data[0].id);
                const existingShare = existingShareResult.data[0];
                const shareId = existingShare.id;
                
                // If updating to pending status, we should create a notification
                // (unless auto_accept/decline is enabled, which is already handled above)
                // Also create notification if share is already pending but being updated (e.g., new months added)
                if (shareStatus === 'pending') {
                    if (existingShare.status !== 'pending') {
                        console.log('[DatabaseService] Share status changed to pending, will create notification');
                        shouldCreateNotification = true;
                    } else {
                        // Share is already pending, but we're updating it (e.g., adding months, changing access level)
                        // Create a notification to alert the recipient of the update
                        console.log('[DatabaseService] Share is already pending but being updated, will create notification');
                        shouldCreateNotification = true;
                    }
                }
                
                const updateData = {
                    access_level: accessLevel,
                    shared_months: JSON.stringify(sharedMonths),
                    shared_pots: sharedPots,
                    shared_settings: sharedSettings,
                    share_all_data: shareAllData,
                    status: shareStatus,
                    updated_at: new Date().toISOString()
                };
                
                // Include conversation_id if available
                if (conversationId !== null) {
                    updateData.conversation_id = conversationId;
                }
                
                console.log('[DatabaseService] Updating existing share with data:', updateData);
                const updateResult = await this.queryUpdate(tableName, shareId, updateData);
                
                if (updateResult.error) {
                    console.error('[DatabaseService] Error updating data share:', updateResult.error);
                    return {
                        success: false,
                        share: null,
                        error: updateResult.error.message || 'Failed to update share'
                    };
                }
                
                share = updateResult.data && updateResult.data.length > 0 ? updateResult.data[0] : existingShare;
                console.log('[DatabaseService] Share updated successfully');
            } else {
                // No existing share, create new one
                console.log('[DatabaseService] No existing share found, creating new share');
                const shareData = {
                    owner_user_id: currentUserId,
                    shared_with_user_id: userResult.userId,
                    access_level: accessLevel,
                    shared_months: JSON.stringify(sharedMonths),
                    shared_pots: sharedPots,
                    shared_settings: sharedSettings,
                    share_all_data: shareAllData,
                    status: shareStatus
                };
                
                // Include conversation_id if available
                if (conversationId !== null) {
                    shareData.conversation_id = conversationId;
                }
                
                const result = await this.queryInsert(tableName, shareData);
                
                if (result.error) {
                    console.error('[DatabaseService] Error creating data share:', result.error);
                    // Check if it's a duplicate key error
                    if (result.error.code === '23505' || result.error.message?.includes('duplicate key')) {
                        console.log('[DatabaseService] Duplicate key error detected, attempting to update existing share');
                        // Try to find and update the existing share
                        const retryResult = await this.querySelect(tableName, {
                            filter: {
                                owner_user_id: currentUserId,
                                shared_with_user_id: userResult.userId
                            },
                            limit: 1
                        });
                        
                        if (retryResult.data && retryResult.data.length > 0) {
                            const existingShare = retryResult.data[0];
                            
                            // If updating to pending status, ensure notification is created
                            if (shareStatus === 'pending') {
                                if (existingShare.status !== 'pending') {
                                    console.log('[DatabaseService] Share status changed to pending (duplicate key path), will create notification');
                                    shouldCreateNotification = true;
                                } else {
                                    console.log('[DatabaseService] Share is already pending but being updated (duplicate key path), will create notification');
                                    shouldCreateNotification = true;
                                }
                            }
                            
                            const updateData = {
                                access_level: accessLevel,
                                shared_months: JSON.stringify(sharedMonths),
                                shared_pots: sharedPots,
                                shared_settings: sharedSettings,
                                share_all_data: shareAllData,
                                status: shareStatus,
                                updated_at: new Date().toISOString()
                            };
                            
                            // Include conversation_id if available
                            if (conversationId !== null) {
                                updateData.conversation_id = conversationId;
                            }
                            
                            const updateResult = await this.queryUpdate(tableName, existingShare.id, updateData);
                            if (updateResult.error) {
                                return {
                                    success: false,
                                    share: null,
                                    error: updateResult.error.message || 'Failed to update share'
                                };
                            }
                            share = updateResult.data && updateResult.data.length > 0 ? updateResult.data[0] : existingShare;
                            console.log('[DatabaseService] Share updated after duplicate key error');
                        } else {
                            return {
                                success: false,
                                share: null,
                                error: result.error.message || 'Failed to create share'
                            };
                        }
                    } else {
                        return {
                            success: false,
                            share: null,
                            error: result.error.message || 'Failed to create share'
                        };
                    }
                } else {
                    share = result.data && result.data.length > 0 ? result.data[0] : null;
                    console.log('[DatabaseService] Share created successfully');
                }
            }

            console.log('[DatabaseService] ========== NOTIFICATION CREATION CHECK ==========');
            console.log('[DatabaseService] Pre-check values:', {
                shouldCreateNotification: shouldCreateNotification,
                hasNotificationProcessor: typeof window.NotificationProcessor !== 'undefined',
                hasShare: !!share,
                shareStatus: share?.status,
                shareId: share?.id,
                recipientUserId: userResult.userId,
                recipientEmail: sharedWithEmail,
                shareCreated: !!share,
                shareIdValue: share?.id,
                shareStatusValue: share?.status
            });
            
            // Always create notification for pending shares, regardless of other conditions
            // This ensures recipients always get notified of share requests
            if (share && share.status === 'pending' && typeof window.NotificationProcessor !== 'undefined') {
                console.log('[DatabaseService] ========== FORCING notification creation for pending share ==========');
                shouldCreateNotification = true;
            }
            
            // Create a message in the conversation for share requests
            if (share && share.status === 'pending' && conversationId && typeof window.MessagingService !== 'undefined') {
                console.log('[DatabaseService] ========== Creating share request message in conversation ==========');
                console.log('[DatabaseService] Message details:', {
                    conversationId: conversationId,
                    senderId: currentUserId,
                    recipientId: userResult.userId,
                    shareId: share.id
                });
                
                try {
                    // Parse shared_months from share if it's a string
                    let parsedSharedMonths = sharedMonths || [];
                    if (share.shared_months) {
                        if (typeof share.shared_months === 'string') {
                            try {
                                parsedSharedMonths = JSON.parse(share.shared_months);
                            } catch (e) {
                                console.warn('[DatabaseService] Error parsing shared_months from share:', e);
                                parsedSharedMonths = [];
                            }
                        } else {
                            parsedSharedMonths = share.shared_months;
                        }
                    }
                    
                    // Format share details for the message
                    const monthsList = parsedSharedMonths.map(m => {
                        if (m.type === 'range') {
                            return `${m.startMonth}/${m.startYear} - ${m.endMonth}/${m.endYear}`;
                        } else {
                            return `${m.month}/${m.year}`;
                        }
                    }).join(', ') || (share.share_all_data || shareAllData ? 'All months' : 'None');
                    
                    const shareMessageContent = `📤 Share Request\n\n` +
                        `Access Level: ${share.access_level || accessLevel}\n` +
                        `Months: ${monthsList}\n` +
                        `${(share.shared_pots || sharedPots || share.share_all_data || shareAllData) ? 'Pots: Yes\n' : ''}` +
                        `${(share.shared_settings || sharedSettings || share.share_all_data || shareAllData) ? 'Settings: Yes\n' : ''}` +
                        `\nShare ID: ${share.id}`;
                    
                    const messageResult = await window.MessagingService.sendMessage(
                        conversationId,
                        currentUserId,
                        userResult.userId,
                        shareMessageContent
                    );
                    
                    if (messageResult.success) {
                        console.log('[DatabaseService] ✅ Share request message created successfully in conversation');
                    } else {
                        console.error('[DatabaseService] ❌ Failed to create share request message:', messageResult.error);
                    }
                } catch (messageError) {
                    console.error('[DatabaseService] ❌ Exception creating share request message:', {
                        error: messageError.message,
                        stack: messageError.stack
                    });
                }
            }
            
            // Still create notification for share requests (for badge count, etc.)
            if (shouldCreateNotification && typeof window.NotificationProcessor !== 'undefined' && share) {
                console.log('[DatabaseService] ========== Creating notification for share request ==========');
                console.log('[DatabaseService] Notification details:', {
                    recipientUserId: userResult.userId,
                    recipientEmail: sharedWithEmail,
                    sharerUserId: currentUserId,
                    shareId: share.id,
                    notificationType: 'share_request',
                    shareStatus: share.status
                });
                
                try {
                    const notificationResult = await window.NotificationProcessor.createAndDeliver(
                        userResult.userId,
                        'share_request',
                        share.id,
                        currentUserId,
                        null,
                        {},
                        conversationId
                    );
                    console.log('[DatabaseService] Notification creation result:', {
                        success: notificationResult.success,
                        notificationId: notificationResult.notification?.id,
                        error: notificationResult.error,
                        notification: notificationResult.notification
                    });
                    if (notificationResult.success) {
                        console.log('[DatabaseService] ✅ Notification created successfully for recipient:', userResult.userId);
                        const updateResult = await this.queryUpdate(tableName, share.id, {
                            notification_sent_at: new Date().toISOString()
                        });
                        if (updateResult.error) {
                            console.warn('[DatabaseService] Failed to update notification_sent_at:', updateResult.error);
                        } else {
                            console.log('[DatabaseService] notification_sent_at updated successfully');
                        }
                    } else {
                        console.error('[DatabaseService] ❌ Failed to create notification for recipient:', notificationResult.error);
                    }
                } catch (notificationError) {
                    console.error('[DatabaseService] ❌ Exception creating notification:', {
                        error: notificationError.message,
                        stack: notificationError.stack
                    });
                }
            } else {
                console.log('[DatabaseService] ========== SKIPPING notification creation ==========');
                console.log('[DatabaseService] Skip reasons:', {
                    shouldCreateNotification: shouldCreateNotification,
                    hasNotificationProcessor: typeof window.NotificationProcessor !== 'undefined',
                    hasShare: !!share,
                    shareStatus: share?.status,
                    shareId: share?.id,
                    recipientUserId: userResult.userId
                });
            }
            
            return {
                success: true,
                share: share,
                error: null
            };
        } catch (error) {
            console.error('[DatabaseService] Exception creating data share:', error);
            return {
                success: false,
                share: null,
                error: error.message || 'An unexpected error occurred'
            };
        }
    },
    
    /**
     * Update a data share
     * @param {number} shareId - Share ID to update
     * @param {string} accessLevel - Access level: 'read', 'read_write', or 'read_write_delete'
     * @param {Array} sharedMonths - Array of month objects or date ranges
     * @param {boolean} sharedPots - Whether to share pots
     * @param {boolean} sharedSettings - Whether to share settings
     * @param {boolean} shareAllData - Whether to share all data (optional, defaults to false)
     * @returns {Promise<{success: boolean, share: Object|null, error: string|null}>}
     */
    async updateDataShare(shareId, accessLevel, sharedMonths, sharedPots, sharedSettings, shareAllData = false) {
        console.log('[DatabaseService] ========== updateDataShare() CALLED ==========');
        console.log('[DatabaseService] Parameters:', {
            shareId: shareId,
            shareIdType: typeof shareId,
            accessLevel: accessLevel,
            sharedMonthsCount: Array.isArray(sharedMonths) ? sharedMonths.length : 'not an array',
            sharedMonths: sharedMonths,
            sharedPots: sharedPots,
            sharedPotsType: typeof sharedPots,
            sharedSettings: sharedSettings,
            sharedSettingsType: typeof sharedSettings,
            shareAllData: shareAllData,
            shareAllDataType: typeof shareAllData
        });
        
        try {
            console.log('[DatabaseService] Getting current user ID...');
            const currentUserId = await this._getCurrentUserId();
            console.log('[DatabaseService] Current user ID:', currentUserId);
            if (!currentUserId) {
                console.error('[DatabaseService] User not authenticated');
                return {
                    success: false,
                    share: null,
                    error: 'User not authenticated'
                };
            }
            
            const tableName = this._getTableName('dataShares');
            console.log('[DatabaseService] Table name:', tableName);
            
            const updateData = {
                access_level: accessLevel,
                shared_months: JSON.stringify(sharedMonths),
                shared_pots: sharedPots,
                shared_settings: sharedSettings,
                share_all_data: shareAllData,
                updated_at: new Date().toISOString()
            };
            console.log('[DatabaseService] Update data object:', updateData);
            console.log('[DatabaseService] Update data JSON stringified months:', updateData.shared_months);
            
            console.log('[DatabaseService] Calling queryUpdate with:', {
                tableName: tableName,
                shareId: shareId,
                updateData: updateData,
                filter: { owner_user_id: currentUserId }
            });
            
            const updateStartTime = Date.now();
            const result = await this.queryUpdate(tableName, shareId, updateData, {
                filter: {
                    owner_user_id: currentUserId
                }
            });
            const updateEndTime = Date.now();
            console.log('[DatabaseService] queryUpdate completed in', (updateEndTime - updateStartTime), 'ms');
            console.log('[DatabaseService] queryUpdate result:', result);
            console.log('[DatabaseService] Result has error:', !!result.error);
            console.log('[DatabaseService] Result has data:', !!result.data);
            console.log('[DatabaseService] Result data length:', result.data ? (Array.isArray(result.data) ? result.data.length : 'not an array') : 'no data');
            
            if (result.error) {
                console.error('[DatabaseService] ❌ Error updating data share');
                console.error('[DatabaseService] Error object:', result.error);
                console.error('[DatabaseService] Error message:', result.error.message);
                console.error('[DatabaseService] Error code:', result.error.code);
                console.error('[DatabaseService] Error details:', result.error.details);
                console.error('[DatabaseService] Error hint:', result.error.hint);
                return {
                    success: false,
                    share: null,
                    error: result.error.message || 'Failed to update share'
                };
            }
            
            const share = result.data && result.data.length > 0 ? result.data[0] : null;
            console.log('[DatabaseService] Extracted share from result:', share);
            console.log('[DatabaseService] Share ID:', share ? share.id : 'no share');
            
            console.log('[DatabaseService] ✅ updateDataShare SUCCESS');
            return {
                success: true,
                share: share,
                error: null
            };
        } catch (error) {
            console.error('[DatabaseService] ========== EXCEPTION IN updateDataShare ==========');
            console.error('[DatabaseService] Exception type:', error.constructor.name);
            console.error('[DatabaseService] Exception message:', error.message);
            console.error('[DatabaseService] Exception stack:', error.stack);
            console.error('[DatabaseService] Full error object:', error);
            console.error('[DatabaseService] ===================================================');
            return {
                success: false,
                share: null,
                error: error.message || 'An unexpected error occurred'
            };
        }
    },
    
    /**
     * Delete a data share
     * @param {number} shareId - Share ID to delete
     * @returns {Promise<{success: boolean, error: string|null}>}
     */
    async deleteDataShare(shareId) {
        console.log('[DatabaseService] deleteDataShare() called', { shareId });
        try {
            const currentUserId = await this._getCurrentUserId();
            if (!currentUserId) {
                console.warn('[DatabaseService] deleteDataShare: User not authenticated');
                return {
                    success: false,
                    error: 'User not authenticated'
                };
            }
            
            const tableName = this._getTableName('dataShares');
            console.log('[DatabaseService] deleteDataShare: Calling queryDelete', { 
                tableName, 
                shareId, 
                ownerUserId: currentUserId 
            });
            
            // queryDelete expects a flat filter object, not nested in 'filter'
            const result = await this.queryDelete(tableName, {
                id: shareId,
                owner_user_id: currentUserId
            });
            
            console.log('[DatabaseService] deleteDataShare: queryDelete result', { 
                success: !result.error, 
                error: result.error,
                deletedCount: result.data?.length || 0
            });
            
            if (result.error) {
                console.error('[DatabaseService] Error deleting data share:', result.error);
                return {
                    success: false,
                    error: result.error.message || 'Failed to delete share'
                };
            }
            
            console.log('[DatabaseService] deleteDataShare: Successfully deleted share', shareId);
            return {
                success: true,
                error: null
            };
        } catch (error) {
            console.error('[DatabaseService] Exception deleting data share:', error);
            return {
                success: false,
                error: error.message || 'An unexpected error occurred'
            };
        }
    },
    
    /**
     * Get all data shares created by current user
     * @returns {Promise<{success: boolean, shares: Array|null, error: string|null}>}
     */
    async getDataSharesCreatedByMe() {
        try {
            const currentUserId = await this._getCurrentUserId();
            if (!currentUserId) {
                return {
                    success: false,
                    shares: null,
                    error: 'User not authenticated'
                };
            }
            
            const tableName = this._getTableName('dataShares');
            const result = await this.querySelect(tableName, {
                filter: {
                    owner_user_id: currentUserId
                },
                order: [{ column: 'created_at', ascending: false }]
            });
            
            if (result.error) {
                console.error('[DatabaseService] Error getting data shares:', result.error);
                return {
                    success: false,
                    shares: null,
                    error: result.error.message || 'Failed to get shares'
                };
            }
            
            const shares = result.data || [];
            
            for (const share of shares) {
                if (typeof share.shared_months === 'string') {
                    try {
                        share.shared_months = JSON.parse(share.shared_months);
                    } catch (e) {
                        share.shared_months = [];
                    }
                }
            }
            
            return {
                success: true,
                shares: shares,
                error: null
            };
        } catch (error) {
            console.error('[DatabaseService] Exception getting data shares:', error);
            return {
                success: false,
                shares: null,
                error: error.message || 'An unexpected error occurred'
            };
        }
    },
    
    /**
     * Get all data shares shared with current user
     * @returns {Promise<{success: boolean, shares: Array|null, error: string|null}>}
     */
    async getDataSharesSharedWithMe() {
        try {
            const currentUserId = await this._getCurrentUserId();
            if (!currentUserId) {
                return {
                    success: false,
                    shares: null,
                    error: 'User not authenticated'
                };
            }
            
            const tableName = this._getTableName('dataShares');
            const result = await this.querySelect(tableName, {
                filter: {
                    shared_with_user_id: currentUserId
                },
                order: [{ column: 'created_at', ascending: false }]
            });
            
            if (result.error) {
                console.error('[DatabaseService] Error getting shared data shares:', result.error);
                return {
                    success: false,
                    shares: null,
                    error: result.error.message || 'Failed to get shares'
                };
            }
            
            const shares = result.data || [];
            
            console.log('[DatabaseService] getDataSharesSharedWithMe - Raw shares from database:', shares.map(s => ({
                id: s.id,
                status: s.status,
                owner_user_id: s.owner_user_id,
                shared_with_user_id: s.shared_with_user_id,
                responded_at: s.responded_at,
                updated_at: s.updated_at
            })));
            
            for (const share of shares) {
                if (typeof share.shared_months === 'string') {
                    try {
                        share.shared_months = JSON.parse(share.shared_months);
                    } catch (e) {
                        share.shared_months = [];
                    }
                }
            }
            
            console.log('[DatabaseService] getDataSharesSharedWithMe - Returning shares:', shares.map(s => ({
                id: s.id,
                status: s.status,
                shareAllData: s.share_all_data
            })));
            
            return {
                success: true,
                shares: shares,
                error: null
            };
        } catch (error) {
            console.error('[DatabaseService] Exception getting shared data shares:', error);
            return {
                success: false,
                shares: null,
                error: error.message || 'An unexpected error occurred'
            };
        }
    },

    /**
     * Update share status (accept, decline, block)
     * @param {number} shareId - Share ID
     * @param {string} status - New status: 'accepted', 'declined', or 'blocked'
     * @returns {Promise<{success: boolean, share: Object|null, error: string|null}>}
     */
    async updateShareStatus(shareId, status) {
        try {
            console.log('[DatabaseService] ========== updateShareStatus() CALLED ==========');
            console.log('[DatabaseService] updateShareStatus() - Start time:', new Date().toISOString());
            console.log('[DatabaseService] updateShareStatus() - Parameters:', { 
                shareId, 
                status, 
                shareIdType: typeof shareId, 
                statusType: typeof status 
            });

            const currentUserId = await this._getCurrentUserId();
            console.log('[DatabaseService] updateShareStatus() - Current user ID:', currentUserId, 'Type:', typeof currentUserId);
            
            if (!currentUserId) {
                console.error('[DatabaseService] updateShareStatus() - User not authenticated');
                return {
                    success: false,
                    share: null,
                    error: 'User not authenticated'
                };
            }

            if (!['accepted', 'declined', 'blocked'].includes(status)) {
                console.error('[DatabaseService] updateShareStatus() - Invalid status:', status);
                return {
                    success: false,
                    share: null,
                    error: 'Invalid status. Must be accepted, declined, or blocked'
                };
            }

            const tableName = this._getTableName('dataShares');
            console.log('[DatabaseService] updateShareStatus() - Table name:', tableName);

            console.log('[DatabaseService] updateShareStatus() - Fetching share from database...');
            const shareResult = await this.querySelect(tableName, {
                filter: { id: shareId },
                limit: 1
            });

            console.log('[DatabaseService] updateShareStatus() - Share query result:', {
                hasError: !!shareResult.error,
                error: shareResult.error,
                hasData: !!shareResult.data,
                dataLength: shareResult.data?.length || 0,
                dataType: Array.isArray(shareResult.data) ? 'array' : typeof shareResult.data
            });

            if (shareResult.error || !shareResult.data || shareResult.data.length === 0) {
                console.error('[DatabaseService] updateShareStatus() - Share not found:', {
                    hasError: !!shareResult.error,
                    error: shareResult.error,
                    hasData: !!shareResult.data,
                    dataLength: shareResult.data?.length || 0
                });
                return {
                    success: false,
                    share: null,
                    error: 'Share not found'
                };
            }

            const share = shareResult.data[0];
            console.log('[DatabaseService] updateShareStatus() - Share found:', {
                shareId: share.id,
                ownerUserId: share.owner_user_id,
                sharedWithUserId: share.shared_with_user_id,
                currentStatus: share.status,
                accessLevel: share.access_level,
                shareAllData: share.share_all_data,
                sharedMonths: share.shared_months,
                createdAt: share.created_at,
                updatedAt: share.updated_at
            });

            console.log('[DatabaseService] updateShareStatus() - Authorization check:', {
                sharedWithUserId: share.shared_with_user_id,
                currentUserId: currentUserId,
                areEqual: share.shared_with_user_id === currentUserId,
                sharedWithType: typeof share.shared_with_user_id,
                currentType: typeof currentUserId,
                sharedWithString: String(share.shared_with_user_id),
                currentString: String(currentUserId)
            });

            if (share.shared_with_user_id !== currentUserId) {
                console.error('[DatabaseService] updateShareStatus() - Not authorized to update this share:', {
                    shareSharedWithUserId: share.shared_with_user_id,
                    currentUserId: currentUserId,
                    match: share.shared_with_user_id === currentUserId
                });
                return {
                    success: false,
                    share: null,
                    error: 'Not authorized to update this share'
                };
            }

            const updateData = {
                status: status,
                responded_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            };

            console.log('[DatabaseService] updateShareStatus() - ========== PREPARING UPDATE ==========');
            console.log('[DatabaseService] updateShareStatus() - Update details:', {
                shareId: shareId,
                tableName: tableName,
                updateData: updateData,
                currentStatus: share.status,
                newStatus: status,
                ownerUserId: share.owner_user_id,
                sharedWithUserId: share.shared_with_user_id,
                currentUserId: currentUserId,
                isRecipient: share.shared_with_user_id === currentUserId,
                isOwner: share.owner_user_id === currentUserId
            });

            // Use RPC function to bypass RLS (similar to notification creation)
            // This avoids policy conflicts and ensures the update succeeds
            console.log('[DatabaseService] updateShareStatus() - Using RPC function to bypass RLS...');
            const rpcParams = {
                p_share_id: shareId,
                p_new_status: status,
                p_user_id: currentUserId
            };
            
            console.log('[DatabaseService] updateShareStatus() - RPC parameters:', JSON.stringify(rpcParams, null, 2));
            console.log('[DatabaseService] updateShareStatus() - Calling queryRpc("update_share_status", ...)');
            const updateStartTime = Date.now();
            const rpcResult = await this.queryRpc('update_share_status', rpcParams);
            const updateDuration = Date.now() - updateStartTime;
            console.log(`[DatabaseService] updateShareStatus() - queryRpc completed in ${updateDuration}ms`);
            
            console.log('[DatabaseService] updateShareStatus() - RPC result:', {
                hasError: !!rpcResult.error,
                error: rpcResult.error,
                hasData: rpcResult.data !== null && rpcResult.data !== undefined,
                data: rpcResult.data,
                dataType: typeof rpcResult.data
            });

            if (rpcResult.error) {
                console.error('[DatabaseService] updateShareStatus() - RPC error:', rpcResult.error);
                return {
                    success: false,
                    share: null,
                    error: rpcResult.error.message || 'Failed to update share status'
                };
            }

            // Extract the updated share from the RPC result
            // The function returns a table, so we get an array with one row
            let updatedShare = null;
            if (Array.isArray(rpcResult.data) && rpcResult.data.length > 0) {
                updatedShare = rpcResult.data[0];
                console.log('[DatabaseService] updateShareStatus() - Extracted share from RPC result:', updatedShare);
            } else if (rpcResult.data && typeof rpcResult.data === 'object' && !Array.isArray(rpcResult.data)) {
                updatedShare = rpcResult.data;
                console.log('[DatabaseService] updateShareStatus() - Using RPC result as share object:', updatedShare);
            } else {
                console.warn('[DatabaseService] updateShareStatus() - Unexpected RPC result format, using original share');
                updatedShare = share;
            }

            // Create a result object that matches the expected format
            const updateResult = {
                error: null,
                data: updatedShare ? [updatedShare] : []
            };

            console.log('[DatabaseService] updateShareStatus() - ========== UPDATE RESULT ==========');
            console.log('[DatabaseService] updateShareStatus() - Update result:', {
                hasError: !!updateResult.error,
                error: updateResult.error,
                hasData: !!updateResult.data,
                dataLength: updateResult.data?.length || 0,
                dataType: Array.isArray(updateResult.data) ? 'array' : typeof updateResult.data,
                returnedData: updateResult.data
            });

            if (updateResult.error) {
                console.error('[DatabaseService] updateShareStatus() - ========== UPDATE FAILED ==========');
                console.error('[DatabaseService] updateShareStatus() - Error details:', {
                    message: updateResult.error.message,
                    fullError: JSON.stringify(updateResult.error, null, 2)
                });
                return {
                    success: false,
                    share: null,
                    error: updateResult.error.message || 'Failed to update share status'
                };
            }

            // updatedShare is already extracted from RPC result above
            if (!updatedShare) {
                console.warn('[DatabaseService] updateShareStatus() - No share returned from RPC, using original share');
                updatedShare = share;
            }
            
            console.log('[DatabaseService] updateShareStatus() - ========== UPDATE SUCCESS ==========');
            console.log('[DatabaseService] updateShareStatus() - Share status updated successfully:', {
                shareId: shareId,
                oldStatus: share.status,
                newStatus: updatedShare.status,
                updatedShare: updatedShare,
                respondedAt: updatedShare.responded_at,
                updatedAt: updatedShare.updated_at
            });
            
            // No need to verify - the RPC function already returns the updated share

            if (typeof window.NotificationProcessor !== 'undefined') {
                const notificationType = status === 'accepted' ? 'share_accepted' : 
                                       status === 'declined' ? 'share_declined' : 'share_blocked';
                
                console.log('[DatabaseService] ========== Creating notification for share status update ==========');
                console.log('[DatabaseService] Notification details:', {
                    notificationType: notificationType,
                    targetUserId: share.owner_user_id,
                    fromUserId: currentUserId,
                    shareId: shareId,
                    shareStatus: status
                });
                console.log('[DatabaseService] User ID comparison:', {
                    ownerUserId: share.owner_user_id,
                    currentUserId: currentUserId,
                    areEqual: share.owner_user_id === currentUserId,
                    ownerType: typeof share.owner_user_id,
                    currentType: typeof currentUserId
                });
                
                const notificationResult = await window.NotificationProcessor.createAndDeliver(
                    share.owner_user_id,
                    notificationType,
                    shareId,
                    currentUserId,
                    null
                );
                if (notificationResult.success) {
                    console.log('[DatabaseService] Notification created successfully for share status update');
                } else {
                    console.error('[DatabaseService] Failed to create notification:', notificationResult.error);
                }
            } else {
                console.warn('[DatabaseService] NotificationProcessor not available, skipping notification creation');
            }

            if (status === 'blocked') {
                await this.blockUser(share.owner_user_id);
            }

            return {
                success: true,
                share: updatedShare,
                error: null
            };
        } catch (error) {
            console.error('[DatabaseService] updateShareStatus() - ========== EXCEPTION IN updateShareStatus() ==========');
            console.error('[DatabaseService] updateShareStatus() - Exception details:', {
                errorMessage: error.message,
                errorStack: error.stack,
                errorName: error.name,
                errorType: typeof error,
                fullError: JSON.stringify(error, Object.getOwnPropertyNames(error), 2)
            });
            return {
                success: false,
                share: null,
                error: error.message || 'An unexpected error occurred'
            };
        }
    },

    /**
     * Block a user (add to blocked list and decline all pending shares from them)
     * @param {string} userIdToBlock - User ID to block
     * @returns {Promise<{success: boolean, error: string|null}>}
     */
    async blockUser(userIdToBlock) {
        try {
            console.log('[DatabaseService] blockUser() called', { userIdToBlock });

            const currentUserId = await this._getCurrentUserId();
            if (!currentUserId) {
                return {
                    success: false,
                    error: 'User not authenticated'
                };
            }

            if (userIdToBlock === currentUserId) {
                return {
                    success: false,
                    error: 'Cannot block yourself'
                };
            }

            const tableName = this._getTableName('blockedUsers');

            const existingResult = await this.querySelect(tableName, {
                filter: {
                    user_id: currentUserId,
                    blocked_user_id: userIdToBlock
                },
                limit: 1
            });

            if (existingResult.data && existingResult.data.length > 0) {
                console.log('[DatabaseService] User already blocked');
                return {
                    success: true,
                    error: null
                };
            }

            const insertResult = await this.queryInsert(tableName, {
                user_id: currentUserId,
                blocked_user_id: userIdToBlock
            });

            if (insertResult.error) {
                console.error('[DatabaseService] Error blocking user:', insertResult.error);
                return {
                    success: false,
                    error: insertResult.error.message || 'Failed to block user'
                };
            }

            const sharesTableName = this._getTableName('dataShares');
            const pendingSharesResult = await this.querySelect(sharesTableName, {
                filter: {
                    owner_user_id: userIdToBlock,
                    shared_with_user_id: currentUserId,
                    status: 'pending'
                }
            });

            if (pendingSharesResult.data && pendingSharesResult.data.length > 0) {
                for (const share of pendingSharesResult.data) {
                    await this.queryUpdate(sharesTableName, share.id, {
                        status: 'declined',
                        responded_at: new Date().toISOString(),
                        updated_at: new Date().toISOString()
                    });
                }
                console.log(`[DatabaseService] Declined ${pendingSharesResult.data.length} pending shares from blocked user`);
            }

            return {
                success: true,
                error: null
            };
        } catch (error) {
            console.error('[DatabaseService] Exception blocking user:', error);
            return {
                success: false,
                error: error.message || 'An unexpected error occurred'
            };
        }
    },

    /**
     * Unblock a user (remove from blocked list)
     * @param {string} userIdToUnblock - User ID to unblock
     * @returns {Promise<{success: boolean, error: string|null}>}
     */
    async unblockUser(userIdToUnblock) {
        try {
            console.log('[DatabaseService] unblockUser() called', { userIdToUnblock });

            const currentUserId = await this._getCurrentUserId();
            if (!currentUserId) {
                return {
                    success: false,
                    error: 'User not authenticated'
                };
            }

            const tableName = this._getTableName('blockedUsers');

            const existingResult = await this.querySelect(tableName, {
                filter: {
                    user_id: currentUserId,
                    blocked_user_id: userIdToUnblock
                },
                limit: 1
            });

            if (!existingResult.data || existingResult.data.length === 0) {
                return {
                    success: true,
                    error: null
                };
            }

            const blockId = existingResult.data[0].id;
            const deleteResult = await this.queryDelete(tableName, blockId);

            if (deleteResult.error) {
                console.error('[DatabaseService] Error unblocking user:', deleteResult.error);
                return {
                    success: false,
                    error: deleteResult.error.message || 'Failed to unblock user'
                };
            }

            return {
                success: true,
                error: null
            };
        } catch (error) {
            console.error('[DatabaseService] Exception unblocking user:', error);
            return {
                success: false,
                error: error.message || 'An unexpected error occurred'
            };
        }
    },

    /**
     * Add a user to friends list
     * @param {string} friendUserId - User ID to add as friend
     * @returns {Promise<{success: boolean, error: string|null}>}
     */
    async addFriend(friendUserId) {
        console.log('[DatabaseService] addFriend() called', { friendUserId });
        try {
            const currentUserId = await this._getCurrentUserId();
            if (!currentUserId) {
                return {
                    success: false,
                    error: 'User not authenticated'
                };
            }

            if (friendUserId === currentUserId) {
                return {
                    success: false,
                    error: 'Cannot add yourself as a friend'
                };
            }

            const tableName = this._getTableName('friends');
            
            // Check if already friends
            const existingResult = await this.querySelect(tableName, {
                filter: {
                    user_id: currentUserId,
                    friend_user_id: friendUserId
                },
                limit: 1
            });

            if (existingResult.error) {
                console.error('[DatabaseService] Error checking existing friend:', existingResult.error);
                return {
                    success: false,
                    error: existingResult.error.message || 'Failed to check existing friend'
                };
            }

            if (existingResult.data && existingResult.data.length > 0) {
                return {
                    success: true,
                    error: null // Already friends, return success
                };
            }

            const insertResult = await this.queryInsert(tableName, {
                user_id: currentUserId,
                friend_user_id: friendUserId
            });

            if (insertResult.error) {
                console.error('[DatabaseService] Error adding friend:', insertResult.error);
                return {
                    success: false,
                    error: insertResult.error.message || 'Failed to add friend'
                };
            }

            console.log('[DatabaseService] Friend added successfully');
            return {
                success: true,
                error: null
            };
        } catch (error) {
            console.error('[DatabaseService] Exception adding friend:', error);
            return {
                success: false,
                error: error.message || 'An unexpected error occurred'
            };
        }
    },

    /**
     * Remove a user from friends list
     * @param {string} friendUserId - User ID to remove from friends
     * @returns {Promise<{success: boolean, error: string|null}>}
     */
    async removeFriend(friendUserId) {
        console.log('[DatabaseService] removeFriend() called', { friendUserId });
        try {
            const currentUserId = await this._getCurrentUserId();
            if (!currentUserId) {
                return {
                    success: false,
                    error: 'User not authenticated'
                };
            }

            const tableName = this._getTableName('friends');
            const deleteResult = await this.queryDelete(tableName, {
                user_id: currentUserId,
                friend_user_id: friendUserId
            });

            if (deleteResult.error) {
                console.error('[DatabaseService] Error removing friend:', deleteResult.error);
                return {
                    success: false,
                    error: deleteResult.error.message || 'Failed to remove friend'
                };
            }

            console.log('[DatabaseService] Friend removed successfully');
            return {
                success: true,
                error: null
            };
        } catch (error) {
            console.error('[DatabaseService] Exception removing friend:', error);
            return {
                success: false,
                error: error.message || 'An unexpected error occurred'
            };
        }
    },

    /**
     * Get list of friends
     * @returns {Promise<{success: boolean, friends: Array, error: string|null}>}
     */
    async getFriends() {
        console.log('[DatabaseService] getFriends() called');
        try {
            const currentUserId = await this._getCurrentUserId();
            if (!currentUserId) {
                return {
                    success: false,
                    friends: [],
                    error: 'User not authenticated'
                };
            }

            const tableName = this._getTableName('friends');
            const result = await this.querySelect(tableName, {
                filter: {
                    user_id: currentUserId
                },
                order: [{ column: 'created_at', ascending: false }]
            });

            if (result.error) {
                console.error('[DatabaseService] Error getting friends:', result.error);
                return {
                    success: false,
                    friends: [],
                    error: result.error.message || 'Failed to get friends'
                };
            }

            return {
                success: true,
                friends: result.data || [],
                error: null
            };
        } catch (error) {
            console.error('[DatabaseService] Exception getting friends:', error);
            return {
                success: false,
                friends: [],
                error: error.message || 'An unexpected error occurred'
            };
        }
    },

    /**
     * Check if a user is in friends list
     * @param {string} friendUserId - User ID to check
     * @returns {Promise<{success: boolean, isFriend: boolean, error: string|null}>}
     */
    async isFriend(friendUserId) {
        console.log('[DatabaseService] isFriend() called', { friendUserId });
        try {
            const currentUserId = await this._getCurrentUserId();
            if (!currentUserId) {
                return {
                    success: false,
                    isFriend: false,
                    error: 'User not authenticated'
                };
            }

            const tableName = this._getTableName('friends');
            const result = await this.querySelect(tableName, {
                filter: {
                    user_id: currentUserId,
                    friend_user_id: friendUserId
                },
                limit: 1
            });

            if (result.error) {
                console.error('[DatabaseService] Error checking if friend:', result.error);
                return {
                    success: false,
                    isFriend: false,
                    error: result.error.message || 'Failed to check if friend'
                };
            }

            return {
                success: true,
                isFriend: result.data && result.data.length > 0,
                error: null
            };
        } catch (error) {
            console.error('[DatabaseService] Exception checking if friend:', error);
            return {
                success: false,
                isFriend: false,
                error: error.message || 'An unexpected error occurred'
            };
        }
    },

    /**
     * Get list of blocked users
     * @returns {Promise<{success: boolean, blockedUsers: Array, error: string|null}>}
     */
    async getBlockedUsers() {
        try {
            console.log('[DatabaseService] getBlockedUsers() called');

            const currentUserId = await this._getCurrentUserId();
            if (!currentUserId) {
                return {
                    success: false,
                    blockedUsers: [],
                    error: 'User not authenticated'
                };
            }

            const tableName = this._getTableName('blockedUsers');
            const result = await this.querySelect(tableName, {
                filter: {
                    user_id: currentUserId
                },
                order: [{ column: 'created_at', ascending: false }]
            });

            if (result.error) {
                console.error('[DatabaseService] Error getting blocked users:', result.error);
                return {
                    success: false,
                    blockedUsers: [],
                    error: result.error.message || 'Failed to get blocked users'
                };
            }

            return {
                success: true,
                blockedUsers: result.data || [],
                error: null
            };
        } catch (error) {
            console.error('[DatabaseService] Exception getting blocked users:', error);
            return {
                success: false,
                blockedUsers: [],
                error: error.message || 'An unexpected error occurred'
            };
        }
    },

    /**
     * Get all data shared with current user, grouped by status
     * @returns {Promise<{success: boolean, data: Object, error: string|null}>}
     */
    async getSharedDataWithMe() {
        try {
            console.log('[DatabaseService] getSharedDataWithMe() called');

            const sharesResult = await this.getDataSharesSharedWithMe();
            if (!sharesResult.success) {
                return sharesResult;
            }

            const shares = sharesResult.shares || [];
            const grouped = {
                pending: [],
                accepted: [],
                declined: [],
                blocked: []
            };

            for (const share of shares) {
                const status = share.status || 'pending';
                if (grouped[status]) {
                    grouped[status].push(share);
                }
            }

            return {
                success: true,
                data: grouped,
                error: null
            };
        } catch (error) {
            console.error('[DatabaseService] Exception getting shared data:', error);
            return {
                success: false,
                data: { pending: [], accepted: [], declined: [], blocked: [] },
                error: error.message || 'An unexpected error occurred'
            };
        }
    },

    /**
     * Get user's notification preferences
     * @returns {Promise<{success: boolean, preferences: Object|null, error: string|null}>}
     */
    async getNotificationPreferences() {
        try {
            if (typeof window.NotificationPreferenceService === 'undefined') {
                throw new Error('NotificationPreferenceService not available');
            }

            const currentUserId = await this._getCurrentUserId();
            if (!currentUserId) {
                return {
                    success: false,
                    preferences: null,
                    error: 'User not authenticated'
                };
            }

            return await window.NotificationPreferenceService.getPreferences(currentUserId);
        } catch (error) {
            console.error('[DatabaseService] Exception getting notification preferences:', error);
            return {
                success: false,
                preferences: null,
                error: error.message || 'An unexpected error occurred'
            };
        }
    },

    /**
     * Update user's notification preferences
     * @param {Object} preferences - Preferences to update
     * @returns {Promise<{success: boolean, preferences: Object|null, error: string|null}>}
     */
    async updateNotificationPreferences(preferences) {
        try {
            if (typeof window.NotificationPreferenceService === 'undefined') {
                throw new Error('NotificationPreferenceService not available');
            }

            const currentUserId = await this._getCurrentUserId();
            if (!currentUserId) {
                return {
                    success: false,
                    preferences: null,
                    error: 'User not authenticated'
                };
            }

            return await window.NotificationPreferenceService.updatePreferences(currentUserId, preferences);
        } catch (error) {
            console.error('[DatabaseService] Exception updating notification preferences:', error);
            return {
                success: false,
                preferences: null,
                error: error.message || 'An unexpected error occurred'
            };
        }
    },

    /**
     * Send a message to another user
     * @param {string} recipientEmail - Email of the recipient
     * @param {string} content - Message content
     * @returns {Promise<{success: boolean, message: Object|null, error: string|null}>}
     */
    async sendMessage(recipientEmail, content) {
        console.log('[DatabaseService] sendMessage() called', { recipientEmail, contentLength: content?.length });
        try {
            const currentUserId = await this._getCurrentUserId();
            if (!currentUserId) {
                return {
                    success: false,
                    message: null,
                    error: 'User not authenticated'
                };
            }

            if (typeof window.MessagingService === 'undefined') {
                throw new Error('MessagingService not available');
            }

            // Find recipient user by email
            console.log('[DatabaseService] Looking up recipient user by email:', recipientEmail);
            const userResult = await this.findUserByEmail(recipientEmail);
            if (!userResult.success || !userResult.userId) {
                console.error('[DatabaseService] Recipient user not found:', recipientEmail);
                return {
                    success: false,
                    message: null,
                    error: `User with email ${recipientEmail} not found`
                };
            }

            const recipientId = userResult.userId;
            console.log('[DatabaseService] Recipient user found:', { recipientId, recipientEmail });

            // Get or create conversation
            console.log('[DatabaseService] Getting or creating conversation between:', { currentUserId, recipientId });
            const conversationResult = await window.MessagingService.getOrCreateConversation(currentUserId, recipientId);
            if (!conversationResult.success) {
                console.error('[DatabaseService] Failed to get or create conversation:', conversationResult.error);
                return {
                    success: false,
                    message: null,
                    error: conversationResult.error || 'Failed to get or create conversation'
                };
            }

            const conversation = conversationResult.conversation;
            if (!conversation || !conversation.id) {
                console.error('[DatabaseService] Conversation missing or missing ID:', conversationResult);
                return {
                    success: false,
                    message: null,
                    error: 'Failed to get conversation ID. ' + (conversationResult.error || 'Unknown error')
                };
            }
            console.log('[DatabaseService] Conversation ready:', { conversationId: conversation.id });

            // Send message
            console.log('[DatabaseService] Sending message via MessagingService');
            const sendResult = await window.MessagingService.sendMessage(conversation.id, currentUserId, recipientId, content);
            console.log('[DatabaseService] Message send result:', { success: sendResult.success, messageId: sendResult.message?.id, error: sendResult.error });
            return sendResult;
        } catch (error) {
            console.error('[DatabaseService] Exception sending message:', error);
            return {
                success: false,
                message: null,
                error: error.message || 'An unexpected error occurred'
            };
        }
    },

    /**
     * Get all conversations for the current user
     * @returns {Promise<{success: boolean, conversations: Array|null, error: string|null}>}
     */
    async getConversations() {
        console.log('[DatabaseService] getConversations() called');
        try {
            const currentUserId = await this._getCurrentUserId();
            if (!currentUserId) {
                console.warn('[DatabaseService] User not authenticated for getConversations');
                return {
                    success: false,
                    conversations: null,
                    error: 'User not authenticated'
                };
            }

            console.log('[DatabaseService] Getting conversations for user:', currentUserId);
            if (typeof window.MessagingService === 'undefined') {
                throw new Error('MessagingService not available');
            }

            const result = await window.MessagingService.getConversations(currentUserId);
            console.log('[DatabaseService] getConversations result:', { 
                success: result.success, 
                conversationCount: result.conversations?.length || 0,
                error: result.error 
            });
            return result;
        } catch (error) {
            console.error('[DatabaseService] Exception getting conversations:', {
                errorMessage: error.message,
                errorStack: error.stack
            });
            return {
                success: false,
                conversations: null,
                error: error.message || 'An unexpected error occurred'
            };
        }
    },

    /**
     * Get messages in a conversation
     * @param {number} conversationId - Conversation ID
     * @param {Object} options - Query options (limit, offset)
     * @returns {Promise<{success: boolean, messages: Array|null, error: string|null}>}
     */
    async getMessages(conversationId, options = {}) {
        console.log('[DatabaseService] getMessages() called', { conversationId, options });
        try {
            if (typeof window.MessagingService === 'undefined') {
                throw new Error('MessagingService not available');
            }

            const result = await window.MessagingService.getMessages(conversationId, options);
            console.log('[DatabaseService] getMessages result:', { 
                success: result.success, 
                messageCount: result.messages?.length || 0,
                error: result.error 
            });
            return result;
        } catch (error) {
            console.error('[DatabaseService] Exception getting messages:', {
                conversationId,
                errorMessage: error.message,
                errorStack: error.stack
            });
            return {
                success: false,
                messages: null,
                error: error.message || 'An unexpected error occurred'
            };
        }
    },

    /**
     * Mark a message as read
     * @param {number} messageId - Message ID
     * @returns {Promise<{success: boolean, error: string|null}>}
     */
    async markMessageAsRead(messageId) {
        console.log('[DatabaseService] markMessageAsRead() called', { messageId });
        try {
            const currentUserId = await this._getCurrentUserId();
            if (!currentUserId) {
                return {
                    success: false,
                    error: 'User not authenticated'
                };
            }

            if (typeof window.MessagingService === 'undefined') {
                throw new Error('MessagingService not available');
            }

            return await window.MessagingService.markMessageAsRead(messageId, currentUserId);
        } catch (error) {
            console.error('[DatabaseService] Exception marking message as read:', error);
            return {
                success: false,
                error: error.message || 'An unexpected error occurred'
            };
        }
    },

    /**
     * Mark all messages in a conversation as read
     * @param {number} conversationId - Conversation ID
     * @returns {Promise<{success: boolean, error: string|null}>}
     */
    async markConversationAsRead(conversationId) {
        console.log('[DatabaseService] markConversationAsRead() called', { conversationId });
        try {
            const currentUserId = await this._getCurrentUserId();
            if (!currentUserId) {
                return {
                    success: false,
                    error: 'User not authenticated'
                };
            }

            if (typeof window.MessagingService === 'undefined') {
                throw new Error('MessagingService not available');
            }

            return await window.MessagingService.markConversationAsRead(conversationId, currentUserId);
        } catch (error) {
            console.error('[DatabaseService] Exception marking conversation as read:', error);
            return {
                success: false,
                error: error.message || 'An unexpected error occurred'
            };
        }
    },

    /**
     * Get unread message count for the current user
     * @returns {Promise<{success: boolean, count: number, error: string|null}>}
     */
    async getUnreadMessageCount() {
        console.log('[DatabaseService] getUnreadMessageCount() called');
        try {
            const currentUserId = await this._getCurrentUserId();
            if (!currentUserId) {
                return {
                    success: false,
                    count: 0,
                    error: 'User not authenticated'
                };
            }

            if (typeof window.MessagingService === 'undefined') {
                throw new Error('MessagingService not available');
            }

            return await window.MessagingService.getUnreadCount(currentUserId);
        } catch (error) {
            console.error('[DatabaseService] Exception getting unread message count:', error);
            return {
                success: false,
                count: 0,
                error: error.message || 'An unexpected error occurred'
            };
        }
    }
};

// Log version on load to confirm which version is running
if (typeof window !== 'undefined') {
    window.DatabaseService = DatabaseService;
    console.log('[DatabaseService] ✅ DatabaseService loaded - VERSION:', DatabaseService.VERSION || 'UNKNOWN');
    console.log('[DatabaseService] DatabaseService loaded at:', new Date().toISOString());
}

