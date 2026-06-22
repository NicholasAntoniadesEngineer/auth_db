/**
 * Database Configuration Helper
 * 
 * Provides utility methods for database services to access configuration properties
 * and injected services. Acts as an abstraction layer over DatabaseModule.config.
 * 
 * Similar to ConfigHelper in the payments module.
 */

const DatabaseConfigHelper = {
    /**
     * Get the configuration object
     * @param {Object} serviceInstance - The service instance calling this method
     * @returns {Object} Configuration object
     * @throws {Error} If configuration is not available
     */
    getConfig(serviceInstance) {
        if (serviceInstance && serviceInstance._config) {
            return serviceInstance._config;
        }
        if (typeof DatabaseModule !== 'undefined' && DatabaseModule.config) {
            return DatabaseModule.config;
        }
        throw new Error('DatabaseConfigHelper: Configuration not available. Ensure DatabaseModule.initialize() has been called.');
    },

    /**
     * Get a service from the configuration
     * @param {Object} serviceInstance - The service instance calling this method
     * @param {string} serviceName - Name of the service to retrieve
     * @returns {Object} Service instance
     * @throws {Error} If service is not found
     */
    getService(serviceInstance, serviceName) {
        const config = this.getConfig(serviceInstance);
        const service = config.services[serviceName];
        if (!service) {
            throw new Error(`DatabaseConfigHelper: ${serviceName} service not found in configuration.`);
        }
        return service;
    },

    /**
     * Get the authentication service
     * @param {Object} serviceInstance - The service instance calling this method
     * @returns {Object} Auth service
     */
    getAuthService(serviceInstance) {
        return this.getService(serviceInstance, 'auth');
    },

    /**
     * Get the database provider type
     * @param {Object} serviceInstance - The service instance calling this method
     * @returns {string} Provider type (e.g., 'supabase')
     */
    getProviderType(serviceInstance) {
        const config = this.getConfig(serviceInstance);
        if (!config.provider || !config.provider.type) {
            throw new Error('DatabaseConfigHelper: Provider type not found in configuration.');
        }
        return config.provider.type;
    },

    /**
     * Get the database provider configuration
     * @param {Object} serviceInstance - The service instance calling this method
     * @returns {Object} Provider configuration
     */
    getProviderConfig(serviceInstance) {
        const config = this.getConfig(serviceInstance);
        if (!config.provider || !config.provider.config) {
            throw new Error('DatabaseConfigHelper: Provider config not found in configuration.');
        }
        return config.provider.config;
    },

    /**
     * Get a table name
     * @param {Object} serviceInstance - The service instance calling this method
     * @param {string} tableKey - Key for the table (e.g., 'userMonths', 'settings')
     * @returns {string} Table name
     */
    getTableName(serviceInstance, tableKey) {
        const config = this.getConfig(serviceInstance);
        if (!config.tables || !config.tables[tableKey]) {
            throw new Error(`DatabaseConfigHelper: Table name for '${tableKey}' not found in configuration.`);
        }
        return config.tables[tableKey];
    },

    /**
     * Get cache configuration
     * @param {Object} serviceInstance - The service instance calling this method
     * @returns {Object} Cache configuration
     */
    getCacheConfig(serviceInstance) {
        const config = this.getConfig(serviceInstance);
        return config.cache || {};
    },

    /**
     * Get application configuration
     * @param {Object} serviceInstance - The service instance calling this method
     * @returns {Object} Application configuration
     */
    getApplicationConfig(serviceInstance) {
        const config = this.getConfig(serviceInstance);
        return config.application || {};
    },

    /**
     * Get logging configuration
     * @param {Object} serviceInstance - The service instance calling this method
     * @returns {Object} Logging configuration
     */
    getLoggingConfig(serviceInstance) {
        const config = this.getConfig(serviceInstance);
        return config.logging || { verbose: false, prefix: '[Database]' };
    },
    
    /**
     * Get the database service
     * @param {Object} serviceInstance - The service instance calling this method
     * @returns {Object} Database service
     */
    getDatabaseService(serviceInstance) {
        if (typeof window !== 'undefined' && window.DatabaseService) {
            return window.DatabaseService;
        }
        throw new Error('DatabaseConfigHelper: DatabaseService not available. Ensure database-service.js is loaded.');
    }
};

if (typeof window !== 'undefined') {
    window.DatabaseConfigHelper = DatabaseConfigHelper;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = DatabaseConfigHelper;
}

