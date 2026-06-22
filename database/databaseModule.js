/**
 * Database Module
 * 
 * Central module for initializing the database system with a given configuration.
 * Similar to PaymentsModule, this allows the database implementation to be
 * swapped out by providing different configurations.
 * 
 * Usage:
 *   await DatabaseModule.initialize(config);
 *   // Now DatabaseService is configured and ready to use
 */

const DatabaseModule = {
    VERSION: '1.0.0',
    config: null,
    initialized: false,

    /**
     * Initialize the database module with a configuration
     * @param {Object} config - Database configuration object
     * @returns {Promise<{success: boolean, error: string|null}>}
     */
    async initialize(config) {
        console.log('[DatabaseModule] ========== INITIALIZATION STARTED ==========');
        console.log('[DatabaseModule] Version:', this.VERSION);
        console.log('[DatabaseModule] Config received:', {
            hasConfig: !!config,
            configType: typeof config,
            hasProvider: !!config?.provider,
            hasServices: !!config?.services,
            hasTables: !!config?.tables,
            hasValidate: typeof config?.validate === 'function'
        });
        
        try {
            // Validate configuration
            if (!config) {
                console.error('[DatabaseModule] ❌ Configuration is null or undefined');
                throw new Error('Configuration is required');
            }
            
            console.log('[DatabaseModule] Step 1: Checking initial service state...');
            console.log('[DatabaseModule] Initial services state:', {
                hasAuthInConfig: !!config.services?.auth,
                authType: typeof config.services?.auth
            });
            
            // Inject services into config BEFORE validation (for money_tracker compatibility)
            console.log('[DatabaseModule] Step 2: Injecting services from window (if available)...');
            console.log('[DatabaseModule] Window services check:', {
                hasWindow: typeof window !== 'undefined',
                hasWindowAuthService: typeof window !== 'undefined' && !!window.AuthService,
                windowAuthServiceType: typeof window !== 'undefined' ? typeof window.AuthService : 'N/A'
            });
            
            if (!config.services.auth && typeof window !== 'undefined' && window.AuthService) {
                config.services.auth = window.AuthService;
                console.log('[DatabaseModule] ✅ Injected window.AuthService into config');
                console.log('[DatabaseModule] AuthService details:', {
                    type: typeof window.AuthService,
                    hasInitialize: typeof window.AuthService?.initialize === 'function',
                    hasIsAuthenticated: typeof window.AuthService?.isAuthenticated === 'function',
                    hasGetCurrentUser: typeof window.AuthService?.getCurrentUser === 'function'
                });
            } else {
                console.log('[DatabaseModule] ⚠️ AuthService not injected:', {
                    alreadyInConfig: !!config.services.auth,
                    windowAvailable: typeof window !== 'undefined',
                    windowHasService: typeof window !== 'undefined' && !!window.AuthService
                });
            }
            
            console.log('[DatabaseModule] Step 3: Services state after injection:', {
                hasAuth: !!config.services.auth,
                authType: typeof config.services.auth
            });
            
            // Now validate configuration (after services are injected)
            console.log('[DatabaseModule] Step 4: Validating configuration...');
            console.log('[DatabaseModule] Validation method check:', {
                hasValidate: typeof config.validate === 'function',
                validateType: typeof config.validate
            });
            
            if (typeof config.validate !== 'function') {
                console.error('[DatabaseModule] ❌ config.validate is not a function:', typeof config.validate);
                throw new Error('Configuration object does not have a validate() method. Ensure DatabaseConfigBase.merge() was used correctly.');
            }
            
            const validation = config.validate();
            console.log('[DatabaseModule] Validation result:', {
                valid: validation.valid,
                errorCount: validation.errors?.length || 0,
                errors: validation.errors || []
            });
            
            if (!validation.valid) {
                console.error('[DatabaseModule] ❌ Configuration validation failed');
                console.error('[DatabaseModule] Validation errors:', validation.errors);
                throw new Error(`Configuration validation failed: ${validation.errors.join(', ')}`);
            }
            
            console.log('[DatabaseModule] ✅ Configuration validation passed');
            
            // Validate services are available
            console.log('[DatabaseModule] Step 5: Final service availability check...');
            if (!config.services.auth) {
                console.error('[DatabaseModule] ❌ Auth service is missing');
                throw new Error('Auth service is required. Provide via config.services.auth or ensure window.AuthService is available.');
            }
            console.log('[DatabaseModule] ✅ Auth service available');
            
            // Store configuration
            console.log('[DatabaseModule] Step 6: Storing config and injecting into DatabaseService...');
            this.config = config;
            console.log('[DatabaseModule] Config stored in DatabaseModule');

            // Inject config into DatabaseService
            if (window.DatabaseService) {
                window.DatabaseService._config = config;
                console.log('[DatabaseModule] ✅ DatabaseService configured with config');
                console.log('[DatabaseModule] DatabaseService details:', {
                    hasConfig: !!window.DatabaseService._config,
                    hasInitialize: typeof window.DatabaseService.initialize === 'function',
                    hasQuerySelect: typeof window.DatabaseService.querySelect === 'function'
                });
            } else {
                console.warn('[DatabaseModule] ⚠️ DatabaseService not found in window');
            }
            
            // Store module reference
            if (typeof window !== 'undefined') {
                window.DatabaseModule = this;
                console.log('[DatabaseModule] ✅ DatabaseModule stored in window');
            }
            
            this.initialized = true;
            console.log('[DatabaseModule] ========== INITIALIZATION SUCCESSFUL ==========');
            console.log('[DatabaseModule] Final state:', {
                initialized: this.initialized,
                hasConfig: !!this.config,
                providerType: this.config?.provider?.type
            });
            
            return {
                success: true,
                error: null
            };
        } catch (error) {
            console.error('[DatabaseModule] ========== INITIALIZATION FAILED ==========');
            console.error('[DatabaseModule] Error:', error);
            return {
                success: false,
                error: error.message || 'Unknown error during initialization'
            };
        }
    },

    /**
     * Check if the module is initialized
     * @returns {boolean}
     */
    isInitialized() {
        return this.initialized;
    },

    /**
     * Get the current configuration
     * @returns {Object|null}
     */
    getConfig() {
        return this.config;
    }
};

if (typeof window !== 'undefined') {
    window.DatabaseModule = DatabaseModule;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = DatabaseModule;
}

