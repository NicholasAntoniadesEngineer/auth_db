/**
 * Database Configuration Base
 * 
 * Base structure for database module configuration.
 * This allows the database module to be reusable across different projects
 * by providing a configuration system similar to the payments module.
 * 
 * To use in a new project:
 * 1. Create a project-specific config file that extends this base
 * 2. Call DatabaseModule.initialize(yourConfig)
 * 3. Use DatabaseService as normal - it will use the configured database
 */

const DatabaseConfigBase = {
    /**
     * Database Provider Configuration
     * Defines which database provider to use and its settings
     */
    provider: {
        type: null, // 'supabase', 'firebase', 'postgres', etc.
        config: null // Provider-specific configuration
    },
    
    /**
     * Services Configuration
     * External services that the database module depends on
     */
    services: {
        auth: null // Authentication service (required)
    },
    
    /**
     * Table Names Configuration
     * Maps logical table names to actual database table names
     */
    tables: {
        userMonths: 'user_months',
        exampleMonths: 'example_months',
        settings: 'settings',
        subscriptions: 'subscriptions',
        subscriptionPlans: 'subscription_plans',
        paymentHistory: 'payment_history'
    },
    
    /**
     * Cache Configuration
     */
    cache: {
        enabled: true,
        duration: 24 * 60 * 60 * 1000, // 24 hours in milliseconds
        storageKey: 'money_tracker_months_cache',
        timestampKey: 'money_tracker_cache_timestamp'
    },
    
    /**
     * Application-Specific Settings
     */
    application: {
        exampleYear: 2045, // Example data year - protected from deletion
        name: 'Database Module'
    },
    
    /**
     * Logging Configuration
     */
    logging: {
        verbose: false,
        prefix: '[Database]'
    },
    
    /**
     * Validation
     * Validates that all required configuration is present
     * @returns {Object} { valid: boolean, errors: string[] }
     */
    validate() {
        const errors = [];
        
        if (!this.provider.type) {
            errors.push('provider.type is required');
        }
        
        if (!this.provider.config) {
            errors.push('provider.config is required');
        }
        
        if (!this.services.auth) {
            errors.push('services.auth is required');
        }
        
        if (!this.tables.userMonths) {
            errors.push('tables.userMonths is required');
        }
        
        if (!this.tables.settings) {
            errors.push('tables.settings is required');
        }
        
        return {
            valid: errors.length === 0,
            errors: errors
        };
    },
    
    /**
     * Merge with another configuration object
     * @param {Object} config - Configuration to merge
     * @returns {Object} Merged configuration
     */
    merge(config) {
        // Store methods before cloning
        const validateMethod = this.validate;
        const mergeMethod = this.merge;
        
        // Create a new object, copying all data properties
        const merged = {};
        
        // Copy all data properties (not methods)
        merged.provider = { ...this.provider };
        merged.services = { ...this.services };
        merged.tables = { ...this.tables };
        merged.cache = { ...this.cache };
        merged.application = { ...this.application };
        merged.logging = { ...this.logging };
        
        // Merge config properties
        if (config.provider) {
            merged.provider = {
                ...merged.provider,
                ...config.provider,
                config: { ...merged.provider.config, ...(config.provider.config || {}) }
            };
        }
        
        if (config.services) {
            merged.services = { ...merged.services, ...config.services };
        }
        
        if (config.tables) {
            merged.tables = { ...merged.tables, ...config.tables };
        }
        
        if (config.cache) {
            merged.cache = { ...merged.cache, ...config.cache };
        }
        
        if (config.application) {
            merged.application = { ...merged.application, ...config.application };
        }
        
        if (config.logging) {
            merged.logging = { ...merged.logging, ...config.logging };
        }
        
        // Add methods to the merged object, bound to it
        if (typeof validateMethod === 'function') {
            merged.validate = function() {
                return validateMethod.call(merged);
            };
        } else {
            throw new Error('validate method not found on DatabaseConfigBase');
        }
        
        if (typeof mergeMethod === 'function') {
            merged.merge = function(newConfig) {
                return mergeMethod.call(merged, newConfig);
            };
        } else {
            throw new Error('merge method not found on DatabaseConfigBase');
        }
        
        return merged;
    }
};

if (typeof window !== 'undefined') {
    window.DatabaseConfigBase = DatabaseConfigBase;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = DatabaseConfigBase;
}

