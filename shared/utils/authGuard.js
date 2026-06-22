/**
 * Authentication Guard
 * Protects routes and ensures only authenticated users can access pages
 * Redirects unauthenticated users to the auth page
 */

const AuthGuard = {
    redirecting: false,
    
    /**
     * Check if user is authenticated and redirect if not
     * @returns {Promise<boolean>} True if authenticated, false if redirected
     */
    async checkAuth() {
        try {
            // Initialize AuthService if not already initialized
            if (!window.AuthService) {
                console.error('[AuthGuard] AuthService not available');
                this.redirectToAuth();
                return false;
            }
            
            // Wait for SupabaseConfig to be available before initializing AuthService
            if (!window.AuthService.client) {
                // Wait for SupabaseConfig to be available (with timeout)
                let waitCount = 0;
                const maxWait = 50; // Wait up to 5 seconds (50 * 100ms)
                while (!window.SupabaseConfig && waitCount < maxWait) {
                    await new Promise(resolve => setTimeout(resolve, 100));
                    waitCount++;
                }
                
                if (!window.SupabaseConfig) {
                    console.warn('[AuthGuard] SupabaseConfig not available after waiting, cannot initialize AuthService');
                    return false;
                }
                
                // Initialize if needed
                await window.AuthService.initialize();
            }
            
            // Wait a bit for session to be loaded after redirect
            // This prevents race conditions where session isn't ready immediately
            await new Promise(resolve => setTimeout(resolve, 100));
            
            // Try to get the session directly to ensure it's loaded
            let hasValidSession = false;
            try {
                const sessionResult = await window.AuthService.client.auth.getSession();
                if (sessionResult.data?.session) {
                    window.AuthService.session = sessionResult.data.session;
                    window.AuthService.currentUser = sessionResult.data.session.user;
                    hasValidSession = true;
                } else {
                    // No session data - clear local state
                    window.AuthService.session = null;
                    window.AuthService.currentUser = null;
                    console.log('[AuthGuard] No session found in database - clearing local state');
                }
            } catch (sessionError) {
                console.warn('[AuthGuard] Error getting session:', sessionError);
                // Session check failed - treat as no session
                window.AuthService.session = null;
                window.AuthService.currentUser = null;
                hasValidSession = false;
            }
            
            // Check if user is authenticated
            const isAuthenticated = window.AuthService.isAuthenticated();
            
            // If no valid session or not authenticated, redirect to sign-in
            if (!hasValidSession || !isAuthenticated) {
                console.log('[AuthGuard] User not authenticated or session missing, redirecting to auth page');
                // Clear any stale local state
                window.AuthService.session = null;
                window.AuthService.currentUser = null;
                this.redirectToAuth();
                return false;
            }
            
            console.log('[AuthGuard] User authenticated:', window.AuthService.getCurrentUser()?.email);

            // Subscription gate (BUSINESS gate, not a security boundary — Supabase RLS is the
            // security boundary). New users get a 30-day trial via the create_trial_subscription
            // trigger, so the app is usable before any Stripe setup. On error we fail OPEN
            // (grant access) so a flaky billing check never locks a paying/trial user out.
            if (window.PaymentsModuleInitPromise) {
                try { await window.PaymentsModuleInitPromise; } catch (e) { /* continue */ }
            }
            if (window.SubscriptionChecker) {
                try {
                    const access = await window.SubscriptionChecker.checkAccess();
                    if (!access.hasAccess && access.status === 'no_subscription') {
                        console.log('[AuthGuard] No subscription/trial found, redirecting to subscription page');
                        this.redirectToPayment();
                        return false;
                    }
                    // trial_expired / expired / cancelled -> allow with reduced privileges (UI gates features)
                } catch (subErr) {
                    console.warn('[AuthGuard] Subscription check failed; allowing access (fail-open business gate):', subErr?.message);
                }
            }

            // Initialize feature-permission tiers (used by the UI to gate Premium features)
            if (window.PermissionService) {
                try { await window.PermissionService.initialize(); } catch (e) { console.warn('[AuthGuard] PermissionService init failed:', e?.message); }
            }

            return true;
        } catch (error) {
            console.error('[AuthGuard] Error checking authentication:', error);
            this.redirectToAuth();
            return false;
        }
    },

    /**
     * Redirect to authentication page
     * @returns {void}
     */
    redirectToAuth() {
        // Prevent multiple redirects
        if (this.redirecting) {
            console.log('[AuthGuard] Already redirecting, skipping duplicate redirectToAuth call.');
            return;
        }
        
        const currentPath = window.location.pathname;
        console.log('[AuthGuard] redirectToAuth - Current path:', currentPath);
        console.log('[AuthGuard] redirectToAuth - Current origin:', window.location.origin);
        
        // Don't redirect if already on auth page
        if (currentPath.includes('auth.html')) {
            console.log('[AuthGuard] Already on auth page, skipping redirect');
            return;
        }
        
        this.redirecting = true;
        
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
        
        console.log('[AuthGuard] Redirecting to auth page:', authUrl);
        console.log('[AuthGuard] Path calculation:', {
            currentPath: currentPath,
            pathParts: pathParts,
            basePathParts: basePathParts,
            basePath: basePath,
            authUrl: authUrl
        });
        
        // Store the intended destination for redirect after login
        const returnUrl = encodeURIComponent(window.location.href);
        window.location.href = `${authUrl}?return=${returnUrl}`;
    },

    /**
     * Redirect to payment/subscription page
     * @returns {void}
     */
    redirectToPayment() {
        if (this.redirecting) {
            console.log('[AuthGuard] Already redirecting, skipping duplicate redirectToPayment call.');
            return;
        }
        
        const currentPath = window.location.pathname;

        // Don't redirect if already on the subscription page
        if (currentPath.includes('subscription.html')) {
            return;
        }

        this.redirecting = true;

        // Resolve the subscription page via the Header module-path helper when available
        let url = '../../payments/views/subscription.html';
        try {
            if (window.Header && typeof window.Header.getModulePath === 'function') {
                url = window.Header.getModulePath('payments') + 'subscription.html';
            }
        } catch (e) {
            /* fall back to the relative path */
        }

        console.log('[AuthGuard] Redirecting to subscription page:', url);
        window.location.href = url;
    },

    /**
     * Protect a route - call this at the start of page initialization
     * @param {Function} onAuthenticated - Callback to execute if authenticated
     * @returns {Promise<void>}
     */
    async protectRoute(onAuthenticated) {
        const isAuthenticated = await this.checkAuth();
        
        if (isAuthenticated && onAuthenticated) {
            await onAuthenticated();
        }
    },

    /**
     * Get the return URL from query parameters
     * @returns {string|null} Return URL or null if not present
     */
    getReturnUrl() {
        const urlParams = new URLSearchParams(window.location.search);
        const returnUrl = urlParams.get('return');
        return returnUrl ? decodeURIComponent(returnUrl) : null;
    },

    /**
     * Redirect to the return URL or default page
     * @returns {void}
     */
    async redirectAfterAuth() {
        console.log('[AuthGuard] ========== REDIRECT AFTER AUTH ==========');
        console.log('[AuthGuard] redirectAfterAuth() called');

        const redirectKey = 'auth_redirecting';
        const redirectTimestamp = 'auth_redirect_timestamp';

        // Check if redirect was recently attempted (within last 2 seconds)
        const lastRedirectTime = sessionStorage.getItem(redirectTimestamp);
        const now = Date.now();
        if (lastRedirectTime && (now - parseInt(lastRedirectTime, 10)) < 2000) {
            console.log('[AuthGuard] Redirect was recently attempted, skipping duplicate call');
            return;
        }

        // Set timestamp to prevent duplicate calls
        sessionStorage.setItem(redirectTimestamp, now.toString());
        console.log('[AuthGuard] Set redirect timestamp to prevent duplicates');

        // Clear the timestamp after a delay
        setTimeout(() => {
            sessionStorage.removeItem(redirectTimestamp);
        }, 3000);

        // NOTE: Device pairing is now handled on auth.html immediately after sign-in
        // This redirect only happens from pages other than auth.html that call redirectAfterAuth()
        console.log('[AuthGuard] Device pairing handled on auth page - proceeding with redirect');

        const returnUrl = this.getReturnUrl();
        console.log('[AuthGuard] Return URL from query params:', returnUrl);
        
        let targetUrl = null;
        
        if (returnUrl) {
            // Check if we're already on the target page
            const currentUrl = window.location.href.split('?')[0];
            const targetUrlParsed = returnUrl.split('?')[0];
            console.log('[AuthGuard] Checking if already on target page:', {
                currentUrl: currentUrl,
                targetUrl: targetUrlParsed
            });
            
            if (currentUrl === targetUrlParsed) {
                console.log('[AuthGuard] Already on target page, skipping redirect');
                sessionStorage.removeItem(redirectTimestamp);
                return;
            }
            targetUrl = returnUrl;
        } else {
            // Default to home page
            // Determine the correct path based on current location
            const currentPath = window.location.pathname;
            let basePath = '';

            // Get all module names from registry
            const modules = window.ModuleRegistry?.getAllModuleNames() || [];

            // Check if we're in any module's views folder
            const inModuleViews = modules.some(mod => currentPath.includes(`/${mod}/views/`));
            if (inModuleViews) {
                basePath = '../../landing/';
            }
            // If we're in ui/views/ (old structure, for compatibility)
            else if (currentPath.includes('/ui/views/')) {
                basePath = '../';
            }
            // If we're at any other level with /views/, assume module structure
            else if (currentPath.includes('/views/')) {
                basePath = '../../landing/';
            }

            const targetPath = `${basePath}index.html`;

            console.log('[AuthGuard] No return URL, using default:', {
                basePath: basePath,
                targetPath: targetPath,
                currentPath: currentPath
            });
            
            // Check if we're already on the target page
            if (currentPath.includes('index.html') || (currentPath.endsWith('/') && !currentPath.includes('/views/'))) {
                console.log('[AuthGuard] Already on home page, skipping redirect');
                sessionStorage.removeItem(redirectTimestamp);
                return;
            }
            
            targetUrl = targetPath;
        }
        
        // Perform the redirect
        if (targetUrl) {
            console.log('[AuthGuard] Performing redirect to:', targetUrl);
            console.log('[AuthGuard] Current location:', window.location.href);
            // Use a small delay to ensure any pending operations complete
            setTimeout(() => {
                console.log('[AuthGuard] Executing redirect now...');
                window.location.href = targetUrl;
            }, 100);
        } else {
            console.error('[AuthGuard] ERROR: No target URL determined for redirect');
        }
    }
};

// Make AuthGuard available globally
if (typeof window !== 'undefined') {
    window.AuthGuard = AuthGuard;
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AuthGuard;
}

