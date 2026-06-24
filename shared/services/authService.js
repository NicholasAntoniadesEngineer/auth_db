/**
 * Authentication Service
 * Handles user authentication, sign up, sign in, sign out, and session management
 * Uses Supabase for authentication with email verification
 */

const AuthService = {
    client: null,
    currentUser: null,
    session: null,
    authStateListener: null,
    sessionValidationInterval: null,
    initialized: false,
    SESSION_CHECK_INTERVAL: 5 * 60 * 1000,
    initializationInProgress: false,
    initializationPromise: null,

    /**
     * Initialize the authentication service
     * Prevents multiple simultaneous initializations
     * @returns {Promise<void>}
     */
    async initialize() {
        // If initialization is already in progress, wait for it
        if (this.initializationInProgress && this.initializationPromise) {
            console.log('[AuthService] Initialization already in progress, waiting...');
            return await this.initializationPromise;
        }

        // If already initialized, return immediately
        if (this.initialized && this.client && this.authStateListener) {
            console.log('[AuthService] Already initialized, skipping');
            return { success: true };
        }
        
        console.log('[AuthService] initialize() called');
        this.initializationInProgress = true;
        
        this.initializationPromise = (async () => {
            try {
                if (!window.SupabaseConfig) {
                    throw new Error('SupabaseConfig not available');
                }
                
                // Reuse existing client if available to avoid multiple instances
                if (!this.client) {
                console.log('[AuthService] Creating new Supabase client...');
                const clientInitStart = Date.now();
                this.client = await window.SupabaseConfig.initialize();
                const clientInitDuration = Date.now() - clientInitStart;
                console.log('[AuthService] Supabase client created in', clientInitDuration, 'ms');
                console.log('[AuthService] Client details:', {
                    hasClient: !!this.client,
                    clientType: this.client?.constructor?.name,
                    hasAuth: !!this.client?.auth,
                    supabaseUrl: this.client?.supabaseUrl,
                    supabaseKey: this.client?.supabaseKey ? this.client.supabaseKey.substring(0, 10) + '...' : 'N/A'
                });
            } else {
                console.log('[AuthService] Reusing existing Supabase client');
                console.log('[AuthService] Existing client details:', {
                    clientType: this.client?.constructor?.name,
                    hasAuth: !!this.client?.auth,
                    supabaseUrl: this.client?.supabaseUrl
                });
            }
            
            // Check for existing session with timeout to prevent hanging
            // Make this non-blocking - if it hangs, we'll continue without session
            const sessionCheckStartTime = Date.now();
            const sessionCheckState = { completed: false }; // Use object to ensure proper closure access
            console.log('[AuthService] ========== SESSION CHECK STARTED ==========');
            console.log('[AuthService] Checking for existing session (non-blocking)...');
            console.log('[AuthService] Session check start time:', new Date().toISOString());
            console.log('[AuthService] Current state before check:', {
                hasClient: !!this.client,
                hasAuth: !!this.client?.auth,
                hasCurrentSession: !!this.session,
                hasCurrentUser: !!this.currentUser,
                currentUserEmail: this.currentUser?.email
            });
            
            // Start session check but don't wait for it - set up listeners first
            const SESSION_CHECK_TIMEOUT_MS = 10000; // 10 seconds - reasonable timeout for network requests
            console.log('[AuthService] Session check timeout configured:', SESSION_CHECK_TIMEOUT_MS, 'ms');
            console.log('[AuthService] Starting Promise.race with getSession() and timeout...');
            
            console.log('[AuthService] ========== CREATING GETSESSION PROMISE ==========');
            console.log('[AuthService] Variable state before getSession():', {
                hasClient: !!this.client,
                hasAuth: !!this.client?.auth,
                sessionCheckStartTime: sessionCheckStartTime,
                sessionCheckState: sessionCheckState,
                sessionCheckStateCompleted: sessionCheckState.completed,
                SESSION_CHECK_TIMEOUT_MS: SESSION_CHECK_TIMEOUT_MS
            });
            
            const getSessionPromise = this.client.auth.getSession();
            console.log('[AuthService] getSession() promise created');
            console.log('[AuthService] getSessionPromise type:', typeof getSessionPromise);
            console.log('[AuthService] getSessionPromise is Promise:', getSessionPromise instanceof Promise);
            
            console.log('[AuthService] ========== CREATING TIMEOUT PROMISE ==========');
            console.log('[AuthService] Variable state before timeoutPromise creation:', {
                sessionCheckStartTime: sessionCheckStartTime,
                sessionCheckState: sessionCheckState,
                sessionCheckStateCompleted: sessionCheckState.completed,
                SESSION_CHECK_TIMEOUT_MS: SESSION_CHECK_TIMEOUT_MS,
                SESSION_CHECK_TIMEOUT_MS_type: typeof SESSION_CHECK_TIMEOUT_MS
            });
            
            // Store timeout ID in a variable that can be accessed from outside the Promise
            let timeoutIdRef = null;
            console.log('[AuthService] timeoutIdRef initialized to:', timeoutIdRef);
            
            console.log('[AuthService] About to create Promise constructor...');
            let timeoutPromise;
            try {
                console.log('[AuthService] ========== ENTERING PROMISE CONSTRUCTOR ==========');
                timeoutPromise = new Promise((_, reject) => {
                    console.log('[AuthService] ========== INSIDE PROMISE CONSTRUCTOR ==========');
                    console.log('[AuthService] Promise constructor executing - checking variable access...');
                    console.log('[AuthService] SESSION_CHECK_TIMEOUT_MS accessible:', typeof SESSION_CHECK_TIMEOUT_MS !== 'undefined' ? SESSION_CHECK_TIMEOUT_MS : 'UNDEFINED');
                    console.log('[AuthService] sessionCheckStartTime accessible:', typeof sessionCheckStartTime !== 'undefined' ? sessionCheckStartTime : 'UNDEFINED');
                    console.log('[AuthService] sessionCheckState accessible:', typeof sessionCheckState !== 'undefined' ? sessionCheckState : 'UNDEFINED');
                    console.log('[AuthService] sessionCheckState.completed accessible:', typeof sessionCheckState !== 'undefined' && typeof sessionCheckState.completed !== 'undefined' ? sessionCheckState.completed : 'UNDEFINED');
                    console.log('[AuthService] reject function accessible:', typeof reject !== 'undefined' ? 'YES' : 'NO');
                    console.log('[AuthService] timeoutIdRef accessible:', typeof timeoutIdRef !== 'undefined' ? timeoutIdRef : 'UNDEFINED');
                    
                console.log('[AuthService] Timeout promise created, will reject after', SESSION_CHECK_TIMEOUT_MS, 'ms');
                    console.log('[AuthService] About to call setTimeout...');
                    
                    try {
                        timeoutIdRef = setTimeout(() => {
                            console.log('[AuthService] ========== INSIDE SETTIMEOUT CALLBACK ==========');
                            console.log('[AuthService] setTimeout callback executing...');
                            console.log('[AuthService] Variable access check in setTimeout callback:');
                            console.log('[AuthService] - sessionCheckStartTime:', typeof sessionCheckStartTime !== 'undefined' ? sessionCheckStartTime : 'UNDEFINED');
                            console.log('[AuthService] - sessionCheckState:', typeof sessionCheckState !== 'undefined' ? sessionCheckState : 'UNDEFINED');
                            console.log('[AuthService] - sessionCheckState.completed:', typeof sessionCheckState !== 'undefined' && typeof sessionCheckState.completed !== 'undefined' ? sessionCheckState.completed : 'UNDEFINED');
                            console.log('[AuthService] - SESSION_CHECK_TIMEOUT_MS:', typeof SESSION_CHECK_TIMEOUT_MS !== 'undefined' ? SESSION_CHECK_TIMEOUT_MS : 'UNDEFINED');
                            
                    const elapsed = Date.now() - sessionCheckStartTime;
                            console.log('[AuthService] Elapsed time calculated:', elapsed, 'ms');
                            
                            if (sessionCheckState.completed) {
                        console.log('[AuthService] Timeout triggered but session check already completed - ignoring timeout');
                        console.log('[AuthService] Timeout occurred', elapsed, 'ms after start (session check completed earlier)');
                        return; // Don't reject if already completed
                    }
                    console.log('[AuthService] ========== TIMEOUT TRIGGERED ==========');
                    console.log('[AuthService] Timeout triggered after', elapsed, 'ms');
                    console.log('[AuthService] Timeout time:', new Date().toISOString());
                    console.log('[AuthService] getSession() did not resolve within timeout period');
                    reject(new Error(`Session check timeout after ${SESSION_CHECK_TIMEOUT_MS / 1000} seconds`));
                }, SESSION_CHECK_TIMEOUT_MS);
                        console.log('[AuthService] setTimeout called successfully, timeoutIdRef set to:', timeoutIdRef);
                    } catch (setTimeoutError) {
                        console.error('[AuthService] ERROR in setTimeout call:', setTimeoutError);
                        console.error('[AuthService] setTimeout error details:', {
                            message: setTimeoutError.message,
                            name: setTimeoutError.name,
                            stack: setTimeoutError.stack
                        });
                        throw setTimeoutError;
                    }
                });
                console.log('[AuthService] Promise created successfully');
                console.log('[AuthService] timeoutIdRef after Promise creation:', timeoutIdRef);
                console.log('[AuthService] timeoutPromise type:', typeof timeoutPromise);
                console.log('[AuthService] timeoutPromise is Promise:', timeoutPromise instanceof Promise);
            } catch (promiseCreationError) {
                console.error('[AuthService] ========== ERROR CREATING TIMEOUT PROMISE ==========');
                console.error('[AuthService] Error creating timeoutPromise:', promiseCreationError);
                console.error('[AuthService] Error details:', {
                    message: promiseCreationError.message,
                    name: promiseCreationError.name,
                    stack: promiseCreationError.stack
                });
                throw promiseCreationError;
            }
            
            // Store timeout ID on the promise after it's created
            console.log('[AuthService] About to set timeoutPromise._timeoutId...');
            console.log('[AuthService] timeoutPromise exists:', typeof timeoutPromise !== 'undefined');
            console.log('[AuthService] timeoutIdRef value:', timeoutIdRef);
            timeoutPromise._timeoutId = timeoutIdRef;
            console.log('[AuthService] timeoutPromise._timeoutId set to:', timeoutPromise._timeoutId);
            
            console.log('[AuthService] ========== CREATING PROMISE.RACE ==========');
            console.log('[AuthService] Variable state before Promise.race:', {
                hasGetSessionPromise: typeof getSessionPromise !== 'undefined',
                getSessionPromiseType: typeof getSessionPromise,
                hasTimeoutPromise: typeof timeoutPromise !== 'undefined',
                timeoutPromiseType: typeof timeoutPromise,
                sessionCheckStartTime: sessionCheckStartTime,
                sessionCheckState: sessionCheckState,
                sessionCheckStateCompleted: sessionCheckState.completed
            });
            
            console.log('[AuthService] About to call Promise.race...');
            const sessionCheckPromise = Promise.race([
                getSessionPromise.then(result => {
                    const elapsed = Date.now() - sessionCheckStartTime;
                    sessionCheckState.completed = true; // Mark as completed
                    console.log('[AuthService] ========== GETSESSION RESOLVED ==========');
                    console.log('[AuthService] getSession() resolved after', elapsed, 'ms');
                    console.log('[AuthService] Resolution time:', new Date().toISOString());
                    console.log('[AuthService] Session check marked as completed - timeout will be ignored if it fires');
                    console.log('[AuthService] getSession() result structure:', {
                        hasData: !!result,
                        hasDataData: !!result?.data,
                        hasSession: !!result?.data?.session,
                        hasError: !!result?.error,
                        errorMessage: result?.error?.message,
                        keys: result ? Object.keys(result) : []
                    });
                    return result;
                }).catch(error => {
                    const elapsed = Date.now() - sessionCheckStartTime;
                    sessionCheckState.completed = true; // Mark as completed even on error
                    console.error('[AuthService] ========== GETSESSION REJECTED ==========');
                    console.error('[AuthService] getSession() rejected after', elapsed, 'ms');
                    console.error('[AuthService] Rejection time:', new Date().toISOString());
                    console.error('[AuthService] Session check marked as completed - timeout will be ignored if it fires');
                    console.error('[AuthService] getSession() error:', {
                        message: error.message,
                        name: error.name,
                        stack: error.stack
                    });
                    throw error;
                }),
                timeoutPromise
            ]).then(result => {
                sessionCheckState.completed = true; // Mark as completed when race resolves
                const elapsed = Date.now() - sessionCheckStartTime;
                console.log('[AuthService] ========== PROMISE.RACE RESOLVED ==========');
                console.log('[AuthService] Promise.race resolved after', elapsed, 'ms');
                console.log('[AuthService] Resolution time:', new Date().toISOString());
                console.log('[AuthService] Result type:', typeof result);
                console.log('[AuthService] Result structure:', {
                    hasData: !!result,
                    hasDataData: !!result?.data,
                    hasSession: !!result?.data?.session,
                    hasError: !!result?.error,
                    keys: result ? Object.keys(result) : []
                });
                
                const { data: { session }, error: sessionError } = result;
                
                console.log('[AuthService] Extracted from result:', {
                    hasSession: !!session,
                    hasSessionError: !!sessionError,
                    sessionErrorMessage: sessionError?.message,
                    sessionUserId: session?.user?.id,
                    sessionUserEmail: session?.user?.email
                });
                
                if (sessionError) {
                    console.warn('[AuthService] ========== SESSION CHECK ERROR ==========');
                    console.warn('[AuthService] Session check error (non-blocking):', sessionError.message);
                    console.warn('[AuthService] Error details:', {
                        message: sessionError.message,
                        code: sessionError.code,
                        status: sessionError.status,
                        name: sessionError.name
                    });
                    console.warn('[AuthService] Preserving existing session state (might be network issue)');
                    console.warn('[AuthService] Current state preserved:', {
                        hasSession: !!this.session,
                        hasCurrentUser: !!this.currentUser
                    });
                    // Don't clear existing session state on error - might be network issue
                    return;
                }
                
                if (session) {
                    console.log('[AuthService] ========== SESSION FOUND ==========');
                    this.session = session;
                    this.currentUser = session.user;
                    console.log('[AuthService] Session and user state updated');
                    console.log('[AuthService] Existing session found for user:', {
                        email: this.currentUser.email,
                        userId: this.currentUser.id,
                        emailConfirmed: this.currentUser.email_confirmed_at,
                        sessionExpiresAt: session.expires_at,
                        sessionExpiresIn: session.expires_in,
                        hasAccessToken: !!session.access_token,
                        hasRefreshToken: !!session.refresh_token
                    });
                    const totalElapsed = Date.now() - sessionCheckStartTime;
                    console.log('[AuthService] Session check completed successfully in', totalElapsed, 'ms');
                    console.log('[AuthService] Timeout would have fired in', SESSION_CHECK_TIMEOUT_MS - totalElapsed, 'ms (but check completed first)');
                } else {
                    console.log('[AuthService] ========== NO SESSION FOUND ==========');
                    console.log('[AuthService] No existing session found');
                    console.log('[AuthService] Clearing session and user state');
                    // Only clear session if we actually got a response saying no session
                    // Don't clear on timeout - might still be valid
                    this.session = null;
                    this.currentUser = null;
                    console.log('[AuthService] Session and user state cleared');
                    const totalElapsed = Date.now() - sessionCheckStartTime;
                    console.log('[AuthService] Session check completed - no session in', totalElapsed, 'ms');
                    console.log('[AuthService] Timeout would have fired in', SESSION_CHECK_TIMEOUT_MS - totalElapsed, 'ms (but check completed first)');
                }
                const finalElapsed = Date.now() - sessionCheckStartTime;
                console.log('[AuthService] ========== SESSION CHECK COMPLETE ==========');
                console.log('[AuthService] Total session check duration:', finalElapsed, 'ms');
                console.log('[AuthService] Session check completed', finalElapsed < SESSION_CHECK_TIMEOUT_MS ? 'before' : 'after', 'timeout');
            });
            console.log('[AuthService] Promise.race created successfully');
            console.log('[AuthService] sessionCheckPromise type:', typeof sessionCheckPromise);
            console.log('[AuthService] sessionCheckPromise is Promise:', sessionCheckPromise instanceof Promise);
            
            console.log('[AuthService] About to attach catch handler to sessionCheckPromise...');
            sessionCheckPromise.catch(error => {
                console.log('[AuthService] ========== SESSION CHECK CATCH HANDLER EXECUTED ==========');
                console.log('[AuthService] Catch handler executing - checking variable access...');
                console.log('[AuthService] sessionCheckStartTime accessible:', typeof sessionCheckStartTime !== 'undefined' ? sessionCheckStartTime : 'UNDEFINED');
                console.log('[AuthService] sessionCheckState accessible:', typeof sessionCheckState !== 'undefined' ? sessionCheckState : 'UNDEFINED');
                
                const elapsed = Date.now() - sessionCheckStartTime;
                sessionCheckState.completed = true; // Mark as completed when catch is called
                console.log('[AuthService] ========== SESSION CHECK CATCH ==========');
                console.log('[AuthService] Promise.race caught error after', elapsed, 'ms');
                console.log('[AuthService] Catch time:', new Date().toISOString());
                console.log('[AuthService] Session check marked as completed');
                console.log('[AuthService] Error details:', {
                    message: error.message,
                    name: error.name,
                    stack: error.stack,
                    isTimeout: error.message && error.message.includes('timeout')
                });
                
                // Timeout during initialization is expected behavior - not an error condition
                // The auth state listener will handle session detection when ready
                if (error.message && error.message.includes('timeout')) {
                    console.log('[AuthService] ========== TIMEOUT HANDLED ==========');
                    console.log('[AuthService] Session check timeout during initialization (non-blocking):', error.message);
                    console.log('[AuthService] Timeout occurred after', elapsed, 'ms (timeout configured for', SESSION_CHECK_TIMEOUT_MS, 'ms)');
                    console.log('[AuthService] Timeout is expected behavior during initialization');
                    console.log('[AuthService] Preserving existing session state:', {
                        hasSession: !!this.session,
                        hasCurrentUser: !!this.currentUser,
                        currentUserEmail: this.currentUser?.email
                    });
                    console.log('[AuthService] Auth state listener will handle session detection when ready');
                    console.log('[AuthService] No action needed - initialization continues');
                } else {
                    console.warn('[AuthService] ========== UNEXPECTED ERROR ==========');
                    console.warn('[AuthService] Session check failed (non-blocking):', error.message);
                    console.warn('[AuthService] Error occurred after', elapsed, 'ms');
                    console.warn('[AuthService] Error is not a timeout - unexpected failure');
                    console.warn('[AuthService] Preserving existing session state');
                }
                // On timeout, don't clear existing session state - might still be valid
                // The auth state listener will handle actual session changes
                // Only clear if we're certain there's no session
                console.log('[AuthService] ========== SESSION CHECK CATCH COMPLETE ==========');
                console.log('[AuthService] Total session check duration:', elapsed, 'ms');
            });
            
            console.log('[AuthService] Session check promise created, running in background');
            console.log('[AuthService] Continuing with initialization (not waiting for session check)');
            
            // Don't await - let it run in background, continue with initialization
            // The auth state listener will pick up the session when it's ready
            
            // Set up auth state listener (only if not already set up)
            if (!this.authStateListener) {
                this.setupAuthStateListener();
            } else {
                console.log('[AuthService] Auth state listener already set up, skipping');
            }
            
            // Set up periodic session validation (only if not already set up)
            if (!this.sessionValidationInterval) {
                this.setupPeriodicSessionValidation();
            } else {
                console.log('[AuthService] Periodic session validation already set up, skipping');
            }

                this.initialized = true; // Mark as fully initialized
                console.log('[AuthService] Initialization completed successfully');
                return { success: true };
            } catch (error) {
                console.error('[AuthService] Initialization error:', {
                    message: error.message,
                    name: error.name,
                    stack: error.stack
                });
                this.initialized = false; // Ensure flag is cleared on error
                throw error;
            } finally {
                this.initializationInProgress = false;
            }
        })();
        
        return await this.initializationPromise;
    },

    /**
     * Set up authentication state listener
     * @returns {void}
     */
    setupAuthStateListener() {
        // Remove existing listener if present (Supabase v2 returns subscription object)
        if (this.authStateListener && typeof this.authStateListener.unsubscribe === 'function') {
            console.log('[AuthService] Removing existing auth state listener');
            try {
                this.authStateListener.unsubscribe();
            } catch (unsubscribeError) {
                console.warn('[AuthService] Error unsubscribing from auth state listener:', unsubscribeError);
            }
            this.authStateListener = null;
        }
        
        console.log('[AuthService] Setting up new auth state listener');
        this.authStateListener = this.client.auth.onAuthStateChange((event, session) => {
            console.log('[AuthService] Auth state changed:', event, {
                hasSession: !!session,
                userEmail: session?.user?.email
            });
            
            if (event === 'INITIAL_SESSION' || event === 'SIGNED_IN' || event === 'TOKEN_REFRESHED') {
                this.session = session;
                this.currentUser = session?.user || null;
                if (this.currentUser) {
                    console.log('[AuthService] User session active:', this.currentUser?.email);
                    // Dispatch signin event for all auth events including INITIAL_SESSION
                    // This allows pages to detect when session is restored from localStorage
                    console.log('[AuthService] Dispatching auth:signin event for:', event);
                    window.dispatchEvent(new CustomEvent('auth:signin', { detail: { user: this.currentUser, event: event } }));
                } else {
                    console.log('[AuthService] No user in session - redirecting to sign-in');
                    // No user in session means session is invalid - redirect to sign-in
                    this.session = null;
                    this.currentUser = null;
                    this._redirectToSignIn();
                }
            } else if (event === 'SIGNED_OUT') {
                this.session = null;
                this.currentUser = null;
                console.log('[AuthService] User signed out - redirecting to sign-in');
                
                // Stop periodic validation when signed out
                this.stopPeriodicSessionValidation();
                
                // Dispatch custom event for other parts of the app
                window.dispatchEvent(new CustomEvent('auth:signout'));
                
                // Always redirect to sign-in page when signed out
                this._redirectToSignIn();
            } else if (event === 'USER_UPDATED' || event === 'PASSWORD_RECOVERY') {
                // These events don't require redirect
                if (session) {
                    this.session = session;
                    this.currentUser = session?.user || null;
                }
            } else {
                // Any other event without a valid session means session is lost
                if (!session) {
                    console.log('[AuthService] Session lost during event:', event, '- redirecting to sign-in');
                    this.session = null;
                    this.currentUser = null;
                    this._redirectToSignIn();
                }
            }
        });
        
        console.log('[AuthService] Auth state listener set up successfully');
    },
    
    /**
     * Set up periodic session validation
     * Checks session validity every few minutes to catch expired sessions
     * @returns {void}
     */
    setupPeriodicSessionValidation() {
        // Clear existing interval if present
        if (this.sessionValidationInterval) {
            clearInterval(this.sessionValidationInterval);
            this.sessionValidationInterval = null;
        }
        
        console.log('[AuthService] Setting up periodic session validation');
        
        // Only set up validation if we have a client
        if (!this.client) {
            console.warn('[AuthService] Cannot set up periodic validation - client not initialized');
            return;
        }
        
        // Run validation check periodically
        this.sessionValidationInterval = setInterval(async () => {
            // Only validate if we think we're authenticated
            if (this.isAuthenticated()) {
                console.log('[AuthService] Periodic session validation check...');
                // Use autoRedirect=true and bypassCache=true for periodic checks
                const validation = await this.validateSession(true, true);
                if (!validation.valid) {
                    console.log('[AuthService] Periodic check found invalid session - redirect will occur');
                } else {
                    console.log('[AuthService] Periodic session validation passed');
                }
            }
        }, this.SESSION_CHECK_INTERVAL);
        
        console.log('[AuthService] Periodic session validation set up successfully');
    },
    
    /**
     * Stop periodic session validation
     * @returns {void}
     */
    stopPeriodicSessionValidation() {
        if (this.sessionValidationInterval) {
            clearInterval(this.sessionValidationInterval);
            this.sessionValidationInterval = null;
            console.log('[AuthService] Periodic session validation stopped');
        }
    },

    /**
     * Sign up a new user with email and password
     * @param {string} email - User email
     * @param {string} password - User password
     * @returns {Promise<{success: boolean, error: string|null, user: Object|null, requiresEmailVerification: boolean, message: string|null}>}
     */
    async signUp(email, password) {
        console.log('[AuthService] signUp called');

        try {
            if (this.isAuthenticated()) {
                await this.signOut();
            }

            if (!this.client) {
                await this.initialize();
            }

            if (!email || !password) {
                return { success: false, error: 'Email and password are required', user: null, requiresEmailVerification: false };
            }

            const trimmedEmail = email.trim();

            // H-2: enforce the strong-password policy BEFORE any account is
            // created. The account password encrypts the at-rest identity-key
            // backup (PBKDF2-SHA256 + AES-256-GCM), so a weak password makes a
            // leaked backup offline-brute-forceable (total E2E break). This is
            // the single source of truth (PasswordCryptoService); the previous
            // length>=8-only gate was insufficient and is replaced here.
            const PasswordCrypto = (typeof window !== 'undefined' && window.PasswordCryptoService)
                || (typeof PasswordCryptoService !== 'undefined' ? PasswordCryptoService : null);
            if (PasswordCrypto && typeof PasswordCrypto.enforcePasswordStrength === 'function') {
                try {
                    PasswordCrypto.enforcePasswordStrength(password);
                } catch (strengthError) {
                    return { success: false, error: strengthError.message, user: null, requiresEmailVerification: false };
                }
            } else if (password.length < 12) {
                // Fail closed to the raised minimum if the crypto service is unavailable.
                return { success: false, error: 'Password must be at least 12 characters', user: null, requiresEmailVerification: false };
            }

            const { data, error } = await this.client.auth.signUp({
                email: trimmedEmail,
                password: password,
                options: {
                    emailRedirectTo: window.location.origin + '/auth/views/auth.html'
                }
            });

            if (error) {
                console.error('[AuthService] Sign up error:', error.message);

                let userFriendlyError = error.message;
                if (error.message?.includes('User already registered')) {
                    userFriendlyError = 'An account with this email already exists. Please sign in instead.';
                } else if (error.message?.includes('Invalid email')) {
                    userFriendlyError = 'Please enter a valid email address.';
                } else if (error.message?.includes('Password')) {
                    userFriendlyError = 'Password does not meet requirements. Please use a stronger password.';
                }

                return { success: false, error: userFriendlyError, user: null, requiresEmailVerification: false };
            }

            if (!data?.user) {
                console.error('[AuthService] Sign up failed - no user data returned');
                return { success: false, error: 'Sign up failed - no user data returned', user: null, requiresEmailVerification: false };
            }

            console.log('[AuthService] Sign up successful, user:', data.user.id.slice(0, 8));

            // Create trial subscription for new user
            await this._createTrialSubscription(data.user.id);

            const requiresEmailVerification = !data.session && data.user.email_confirmed_at === null;

            if (data.session) {
                this.currentUser = data.user;
                this.session = data.session;
                console.log('[AuthService] User signed in immediately (no email verification)');
                return { success: true, error: null, user: data.user, requiresEmailVerification: false };
            }

            if (requiresEmailVerification) {
                console.log('[AuthService] Email verification required');
                return {
                    success: true,
                    error: null,
                    user: data.user,
                    requiresEmailVerification: true,
                    message: 'Account created! Please check your email to verify your account before signing in.'
                };
            }

            // No session but email confirmed (unexpected but handled)
            return {
                success: true,
                error: null,
                user: data.user,
                requiresEmailVerification: false,
                message: 'Account created successfully. Please sign in.'
            };
        } catch (error) {
            console.error('[AuthService] Sign up exception:', error.message);
            return { success: false, error: error.message || 'An unexpected error occurred', user: null, requiresEmailVerification: false };
        }
    },

    /**
     * Create trial subscription for a new user
     * @private
     * @param {string} userId - User ID
     */
    async _createTrialSubscription(userId) {
        if (!window.SubscriptionService) {
            console.warn('[AuthService] SubscriptionService not available');
            return;
        }
        try {
            const result = await window.SubscriptionService.createTrialSubscription(userId);
            if (result.success) {
                console.log('[AuthService] Trial subscription created');
            } else {
                console.warn('[AuthService] Failed to create trial subscription:', result.error);
            }
        } catch (error) {
            console.warn('[AuthService] Trial subscription error:', error.message);
        }
    },

    /**
     * Sign in an existing user with email and password
     * @param {string} email - User email
     * @param {string} password - User password
     * @returns {Promise<{success: boolean, error: string|null, user: Object|null}>}
     */
    async signIn(email, password) {
        console.log('[AuthService] signIn called');

        try {
            if (!this.client) {
                await this.initialize();
                if (!this.client) {
                    return { success: false, error: 'Authentication service not available. Please refresh the page.', user: null };
                }
            }

            if (!email || !password) {
                return { success: false, error: 'Email and password are required', user: null };
            }

            const { data, error } = await this.client.auth.signInWithPassword({
                email: email.trim(),
                password: password
            });

            if (error) {
                console.error('[AuthService] Sign in error:', error.message);
                return { success: false, error: error.message, user: null };
            }

            if (!data?.user || !data?.session) {
                return { success: false, error: 'Sign in failed - invalid response', user: null };
            }

            this.currentUser = data.user;
            this.session = data.session;
            window.dispatchEvent(new CustomEvent('auth:signin', { detail: { user: this.currentUser } }));

            console.log('[AuthService] Sign in successful:', this.currentUser.email);
            return { success: true, error: null, user: this.currentUser };
        } catch (error) {
            console.error('[AuthService] Sign in exception:', error.message);
            return { success: false, error: error.message || 'An unexpected error occurred', user: null };
        }
    },

    /**
     * Sign out the current user
     * Forcefully stops all operations, clears state immediately, and redirects
     * Does not wait for server confirmation - forces immediate logout
     * @returns {Promise<{success: boolean, error: string|null}>}
     */
    async signOut() {
        console.log('[AuthService] ========== FORCE SIGN OUT INITIATED ==========');
        
        // Stop all ongoing operations immediately (don't wait)
        this.stopPeriodicSessionValidation();
        
        // Clear local state immediately (before any async operations)
        this.currentUser = null;
        this.session = null;
        console.log('[AuthService] Local state cleared immediately');
        
        // Clear Supabase session data from localStorage BEFORE redirect
        // This prevents Supabase from auto-restoring the session on page reload
        // Supabase stores session with keys like: sb-<project-ref>-auth-token
        try {
            const supabaseUrl = this.client?.supabaseUrl || window.SupabaseConfig?.PROJECT_URL || '';
            const projectRef = supabaseUrl.split('//')[1]?.split('.')[0] || '';
            const sessionKey = projectRef ? `sb-${projectRef}-auth-token` : null;
            if (sessionKey) {
                console.log('[AuthService] Clearing Supabase session from localStorage:', sessionKey);
                localStorage.removeItem(sessionKey);
            }

            // Also clear any other Supabase-related auth keys
            const keysToRemove = [];
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                if (key && (key.startsWith('sb-') && (key.includes('auth') || key.includes('token')))) {
                    keysToRemove.push(key);
                }
            }
            keysToRemove.forEach(key => {
                console.log('[AuthService] Removing Supabase localStorage key:', key);
                localStorage.removeItem(key);
            });
            
            console.log('[AuthService] Cleared', keysToRemove.length + 1, 'Supabase session keys from localStorage');
        } catch (clearError) {
            console.warn('[AuthService] Error clearing Supabase storage:', clearError);
        }
        
        // Dispatch sign out event immediately
        window.dispatchEvent(new CustomEvent('auth:signout'));
        console.log('[AuthService] Sign out event dispatched');
        
        // Attempt server sign-out in background with timeout (don't block on this)
        if (this.client && this.client.auth) {
            Promise.race([
                this.client.auth.signOut(),
                new Promise((_, reject) => 
                    setTimeout(() => reject(new Error('Server sign out timeout')), 2000)
                )
            ]).then(result => {
                if (result && result.error) {
                    console.warn('[AuthService] Server sign out returned error (non-blocking):', result.error.message);
                } else {
                    console.log('[AuthService] Server confirmed sign out (background)');
                }
            }).catch(error => {
                // Timeout or error - continue with logout anyway
                console.warn('[AuthService] Server sign out timeout/error (non-blocking):', error.message);
            });
        }
        
        // SECURITY (H-NEW-1): actively destroy local E2E secret state BEFORE the
        // redirect. Clearing in-memory user/session + localStorage above does NOT
        // touch the encryption IndexedDB (MoneyTrackerEncryption), which holds the
        // wrapped identity secret, ratchet states, the decrypted-message-key
        // archive, prekey secrets, session keys AND the at-rest AES-GCM wrap key
        // (the wrap key auto-loads with no auth gate, so a local-access attacker
        // could otherwise recover the identity secret + full history). Wipe it.
        //
        // Use deleteDatabase() (not clearAll()) so the wrap_keys store is dropped
        // too — clearAll() intentionally preserves the usable wrap key. These calls
        // are AWAITED so the redirect cannot race a fire-and-forget wipe, and each
        // is try/catch-wrapped so any failure still proceeds to the redirect.
        //
        // NO LOCKOUT: this is safe because the identity is also held in the
        // server-side, password-encrypted backup (identity_key_backups). On the
        // next sign-in KeyManagementService.initialize() finds no local keys +
        // an existing backup → needsRestore, and restoreFromPassword() re-derives
        // the identity (and re-creates the wrap key) from that backup. Only the
        // plaintext-equivalent decrypted-message-key archive and forward-secrecy
        // ratchet state are not re-derived — exactly what should not survive logout.
        try {
            if (window.KeyStorageService && typeof window.KeyStorageService.deleteDatabase === 'function') {
                console.log('[AuthService] Wiping encryption IndexedDB (deleteDatabase)...');
                // F-1: never let a blocked/slow IndexedDB delete strand the redirect.
                // A second open tab makes the delete fire `onblocked` (now resolved,
                // not pending) but it can still be slow; mirror the best-effort
                // server-sign-out pattern above and Promise.race the wipe against a
                // 1.5 s timeout so the redirect ALWAYS proceeds. The browser keeps the
                // delete queued, so the key DB is still wiped once other tabs close.
                await Promise.race([
                    window.KeyStorageService.deleteDatabase(),
                    new Promise((resolve) =>
                        setTimeout(() => resolve({ deleted: false, timedOut: true }), 1500)
                    )
                ]);
                console.log('[AuthService] Encryption IndexedDB wipe issued');
            }
        } catch (wipeError) {
            console.warn('[AuthService] Failed to wipe encryption IndexedDB (continuing to redirect):', wipeError);
        }
        try {
            if (window.BudgetKeyService && typeof window.BudgetKeyService.clearCache === 'function') {
                console.log('[AuthService] Clearing BudgetKeyService cache...');
                window.BudgetKeyService.clearCache();
            }
        } catch (cacheError) {
            console.warn('[AuthService] Failed to clear BudgetKeyService cache (continuing to redirect):', cacheError);
        }

        // Determine redirect path using absolute URL (works with file:// protocol)
        const baseUrl = window.location.origin;
        const currentPath = window.location.pathname;
        const pathParts = currentPath.split('/').filter(p => p && p !== 'index.html');

        // Get all module names from registry
        const modules = window.ModuleRegistry?.getAllModuleNames() || [];

        // Find the base path (everything before any known module or 'ui')
        let basePathParts = [];
        for (let i = 0; i < pathParts.length; i++) {
            if (pathParts[i] === 'ui' || modules.includes(pathParts[i])) {
                break;
            }
            basePathParts.push(pathParts[i]);
        }

        const basePath = basePathParts.length > 0 ? basePathParts.join('/') + '/' : '';
        const authPath = `${baseUrl}/${basePath}auth/views/auth.html`;
        
        console.log('[AuthService] Force redirecting to:', authPath);
        console.log('[AuthService] ========== FORCE SIGN OUT COMPLETE ==========');
        
        // Force immediate redirect - don't wait for anything
        window.location.href = authPath;
        
        // Return immediately (redirect will happen before this)
        return { success: true, error: null };
    },
    
    /**
     * Redirect to sign-in page
     * Private helper method
     * Always redirects directly to auth.html using absolute URL
     * @private
     */
    _redirectToSignIn() {
        console.log('[AuthService] ========== REDIRECT TO SIGN IN ==========');
        const currentPath = window.location.pathname;
        console.log('[AuthService] Current path:', currentPath);
        
        // Don't redirect if already on auth page
        if (currentPath.includes('auth.html')) {
            console.log('[AuthService] Already on auth page, skipping redirect');
            return;
        }
        
        // Construct absolute URL to avoid path resolution issues
        const baseUrl = window.location.origin;
        const pathParts = currentPath.split('/').filter(p => p && p !== 'index.html');

        // Get all module names from registry
        const modules = window.ModuleRegistry?.getAllModuleNames() || [];

        // Find the base path (everything before any known module or 'ui')
        let basePathParts = [];
        for (let i = 0; i < pathParts.length; i++) {
            if (pathParts[i] === 'ui' || modules.includes(pathParts[i])) {
                break;
            }
            basePathParts.push(pathParts[i]);
        }

        // Construct the auth URL
        const basePath = basePathParts.length > 0 ? basePathParts.join('/') + '/' : '';
        const authUrl = `${baseUrl}/${basePath}auth/views/auth.html`;
        
        console.log('[AuthService] Redirecting to:', authUrl);
        console.log('[AuthService] Path calculation:', {
            currentPath: currentPath,
            pathParts: pathParts,
            basePathParts: basePathParts,
            basePath: basePath,
            authUrl: authUrl
        });
        console.log('[AuthService] Executing redirect now...');
        
        // Direct redirect - no delays, no AuthGuard logic
        window.location.href = authUrl;
    },

    /**
     * Get the current authenticated user
     * @returns {Object|null} Current user object or null if not authenticated
     */
    getCurrentUser() {
        return this.currentUser;
    },

    /**
     * Get the current session
     * @returns {Object|null} Current session object or null if not authenticated
     */
    getSession() {
        return this.session;
    },

    /**
     * Check if user is authenticated
     * @returns {boolean} True if user is authenticated, false otherwise
     */
    isAuthenticated() {
        return this.currentUser !== null && this.session !== null;
    },
    
    /**
     * Validate and refresh the current session
     * Checks if session exists and is valid, refreshes if needed
     * IMPORTANT: No caching - always checks server for "works every time" reliability
     * @param {boolean} autoRedirect - If true, automatically redirect to sign-in on validation failure (default: false)
     * @returns {Promise<{valid: boolean, session: Object|null, error: string|null}>}
     */
    async validateSession(autoRedirect = false) {
        try {
            if (!this.client) {
                console.warn('[AuthService] Client not initialized during session validation');
                const result = { valid: false, session: null, error: 'Auth service not initialized' };
                if (autoRedirect) {
                    this.currentUser = null;
                    this.session = null;
                    this._redirectToSignIn();
                }
                return result;
            }

            // Get current session from Supabase - ALWAYS check server
            let sessionData, error;
            try {
                const response = await this.client.auth.getSession();
                sessionData = response.data;
                error = response.error;
            } catch (networkError) {
                // CHANGED: Network error INVALIDATES session instead of preserving
                // This ensures "works every time" reliability - no stale sessions
                console.error('[AuthService] Network error during session check - invalidating session:', networkError.message);
                const result = {
                    valid: false,
                    session: null,
                    error: 'Network error - cannot verify session'
                };
                if (autoRedirect) {
                    this.currentUser = null;
                    this.session = null;
                    this._redirectToSignIn();
                }
                return result;
            }

            if (error) {
                console.warn('[AuthService] Error getting session during validation:', error.message);
                const result = { valid: false, session: null, error: error.message };
                if (autoRedirect) {
                    this.currentUser = null;
                    this.session = null;
                    this._redirectToSignIn();
                }
                return result;
            }

            const session = sessionData?.session;

            if (!session) {
                console.log('[AuthService] No session found during validation');
                const result = { valid: false, session: null, error: 'No active session' };
                if (autoRedirect) {
                    this.currentUser = null;
                    this.session = null;
                    this._redirectToSignIn();
                }
                return result;
            }

            // Check if session is expired
            if (session.expires_at && session.expires_at * 1000 < Date.now()) {
                console.log('[AuthService] Session expired - attempting refresh');
                try {
                    const refreshResult = await this.refreshSession();
                    if (!refreshResult.success) {
                        console.log('[AuthService] Session refresh failed');
                        const result = { valid: false, session: null, error: 'Session expired and refresh failed' };
                        if (autoRedirect) {
                            this.currentUser = null;
                            this.session = null;
                            this._redirectToSignIn();
                        }
                        return result;
                    }
                    // Refresh successful, return updated session
                    return { valid: true, session: this.session, error: null };
                } catch (refreshError) {
                    console.error('[AuthService] Session refresh exception:', refreshError);
                    const result = { valid: false, session: null, error: 'Session refresh failed' };
                    if (autoRedirect) {
                        this.currentUser = null;
                        this.session = null;
                        this._redirectToSignIn();
                    }
                    return result;
                }
            }

            // Session is valid - update local state
            this.session = session;
            this.currentUser = session.user;
            return { valid: true, session: session, error: null };

        } catch (error) {
            // CHANGED: Exceptions INVALIDATE session instead of preserving
            // This ensures consistent security behavior
            console.error('[AuthService] Session validation exception:', error);
            const result = { valid: false, session: null, error: error.message || 'Session validation failed' };
            if (autoRedirect) {
                this.currentUser = null;
                this.session = null;
                this._redirectToSignIn();
            }
            return result;
        }
    },

    /**
     * Get the access token for authenticated requests
     * @returns {string|null} Access token or null if not authenticated
     */
    getAccessToken() {
        return this.session?.access_token || null;
    },

    /**
     * Refresh the current session
     * @returns {Promise<{success: boolean, error: string|null}>}
     */
    async refreshSession() {
        try {
            if (!this.client) {
                return { success: false, error: 'Auth service not initialized' };
            }
            
            const { data, error } = await this.client.auth.refreshSession();
            
            if (error) {
                console.error('[AuthService] Refresh session error:', error);
                return { success: false, error: error.message };
            }
            
            if (data.session) {
                this.session = data.session;
                this.currentUser = data.session.user;
                return { success: true, error: null };
            }
            
            return { success: false, error: 'No session data returned' };
        } catch (error) {
            console.error('[AuthService] Refresh session exception:', error);
            return { success: false, error: error.message || 'An unexpected error occurred' };
        }
    },

    /**
     * Send a password reset email
     * @param {string} email - User's email address
     * @returns {Promise<{success: boolean, error: string|null}>}
     */
    async resetPassword(email) {
        try {
            if (!this.client) {
                return { success: false, error: 'Auth service not initialized' };
            }

            console.log('[AuthService] Sending password reset email to:', email);
            const { error } = await this.client.auth.resetPasswordForEmail(email, {
                redirectTo: window.location.origin + '/auth/views/auth.html'
            });

            if (error) {
                console.error('[AuthService] Reset password error:', error);
                return { success: false, error: error.message };
            }

            console.log('[AuthService] Password reset email sent');
            return { success: true, error: null };
        } catch (error) {
            console.error('[AuthService] Reset password exception:', error);
            return { success: false, error: error.message || 'An unexpected error occurred' };
        }
    },

    /**
     * Update the current user's password
     * @param {string} newPassword - The new password
     * @returns {Promise<{success: boolean, error: string|null}>}
     */
    async updatePassword(newPassword) {
        try {
            if (!this.client) {
                return { success: false, error: 'Auth service not initialized' };
            }

            // H-2: the new password will re-encrypt the identity-key backup, so
            // it must satisfy the same strong-password policy as signup before
            // we commit the change. Single source of truth: PasswordCryptoService.
            const PasswordCrypto = (typeof window !== 'undefined' && window.PasswordCryptoService)
                || (typeof PasswordCryptoService !== 'undefined' ? PasswordCryptoService : null);
            if (PasswordCrypto && typeof PasswordCrypto.enforcePasswordStrength === 'function') {
                try {
                    PasswordCrypto.enforcePasswordStrength(newPassword);
                } catch (strengthError) {
                    return { success: false, error: strengthError.message };
                }
            } else if (!newPassword || newPassword.length < 12) {
                return { success: false, error: 'Password must be at least 12 characters' };
            }

            console.log('[AuthService] Updating user password');
            const { error } = await this.client.auth.updateUser({ password: newPassword });

            if (error) {
                console.error('[AuthService] Update password error:', error);
                return { success: false, error: error.message };
            }

            console.log('[AuthService] Password updated successfully');
            return { success: true, error: null };
        } catch (error) {
            console.error('[AuthService] Update password exception:', error);
            return { success: false, error: error.message || 'An unexpected error occurred' };
        }
    }
};

// Make AuthService available globally
if (typeof window !== 'undefined') {
    window.AuthService = AuthService;
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AuthService;
}
