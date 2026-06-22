/**
 * Database Module Initialization Script
 * 
 * This script initializes the database module with the project-specific configuration.
 * Include this script after all database dependencies are loaded.
 * 
 * For the money_tracker project, this uses MoneyTrackerDatabaseConfig.
 * For other projects, create a similar config file and update the import.
 * 
 * This script creates a global promise that can be awaited by other scripts.
 */

// Create a global promise for initialization
window.DatabaseModuleInitPromise = (async function() {
    console.log('[DatabaseInit] ========== DATABASE MODULE INITIALIZATION ==========');
    console.log('[DatabaseInit] Start time:', new Date().toISOString());
    
    try {
        // Wait for required dependencies
        console.log('[DatabaseInit] Step 1: Waiting for config dependencies...');
        let waitCount = 0;
        const maxWait = 50; // 5 seconds
        
        while ((typeof DatabaseConfigBase === 'undefined' || 
                typeof MoneyTrackerDatabaseConfig === 'undefined' ||
                typeof DatabaseModule === 'undefined') && 
               waitCount < maxWait) {
            await new Promise(resolve => setTimeout(resolve, 100));
            waitCount++;
            if (waitCount % 10 === 0) {
                console.log('[DatabaseInit] Still waiting for dependencies...', {
                    waitCount,
                    hasDatabaseConfigBase: typeof DatabaseConfigBase !== 'undefined',
                    hasMoneyTrackerConfig: typeof MoneyTrackerDatabaseConfig !== 'undefined',
                    hasDatabaseModule: typeof DatabaseModule !== 'undefined'
                });
            }
        }
        
        console.log('[DatabaseInit] Dependency check complete after', waitCount * 100, 'ms');
        console.log('[DatabaseInit] Dependencies status:', {
            hasDatabaseConfigBase: typeof DatabaseConfigBase !== 'undefined',
            hasMoneyTrackerConfig: typeof MoneyTrackerDatabaseConfig !== 'undefined',
            hasDatabaseModule: typeof DatabaseModule !== 'undefined'
        });
        
        if (typeof DatabaseConfigBase === 'undefined') {
            console.error('[DatabaseInit] ❌ DatabaseConfigBase not found after', waitCount * 100, 'ms');
            throw new Error('DatabaseConfigBase not found');
        }
        console.log('[DatabaseInit] ✅ DatabaseConfigBase found');
        
        if (typeof MoneyTrackerDatabaseConfig === 'undefined') {
            console.error('[DatabaseInit] ❌ MoneyTrackerDatabaseConfig not found after', waitCount * 100, 'ms');
            throw new Error('MoneyTrackerDatabaseConfig not found');
        }
        console.log('[DatabaseInit] ✅ MoneyTrackerDatabaseConfig found');
        console.log('[DatabaseInit] MoneyTrackerDatabaseConfig details:', {
            hasProvider: !!MoneyTrackerDatabaseConfig.provider,
            hasServices: !!MoneyTrackerDatabaseConfig.services,
            hasTables: !!MoneyTrackerDatabaseConfig.tables,
            hasValidate: typeof MoneyTrackerDatabaseConfig.validate === 'function'
        });
        
        if (typeof DatabaseModule === 'undefined') {
            console.error('[DatabaseInit] ❌ DatabaseModule not found after', waitCount * 100, 'ms');
            throw new Error('DatabaseModule not found');
        }
        console.log('[DatabaseInit] ✅ DatabaseModule found');
        console.log('[DatabaseInit] DatabaseModule details:', {
            version: DatabaseModule.VERSION,
            hasInitialize: typeof DatabaseModule.initialize === 'function',
            initialized: DatabaseModule.initialized
        });
        
        // Wait for DatabaseService to be loaded
        console.log('[DatabaseInit] Step 2: Waiting for DatabaseService to load...');
        let serviceWaitCount = 0;
        const maxServiceWait = 50; // 5 seconds
        while (!window.DatabaseService && serviceWaitCount < maxServiceWait) {
            await new Promise(resolve => setTimeout(resolve, 100));
            serviceWaitCount++;
            if (serviceWaitCount % 10 === 0) {
                console.log('[DatabaseInit] Still waiting for DatabaseService...', {
                    serviceWaitCount,
                    hasDatabaseService: !!window.DatabaseService
                });
            }
        }
        
        console.log('[DatabaseInit] Service wait complete after', serviceWaitCount * 100, 'ms');
        console.log('[DatabaseInit] Services status:', {
            hasDatabaseService: !!window.DatabaseService,
            databaseServiceType: typeof window.DatabaseService
        });
        
        if (!window.DatabaseService) {
            console.error('[DatabaseInit] ❌ DatabaseService not loaded after waiting', serviceWaitCount * 100, 'ms');
            throw new Error('DatabaseService not loaded');
        }
        console.log('[DatabaseInit] ✅ DatabaseService loaded');
        
        // Wait for AuthService
        console.log('[DatabaseInit] Step 3: Checking for AuthService...');
        console.log('[DatabaseInit] Window services check:', {
            hasAuthService: !!window.AuthService,
            authServiceType: typeof window.AuthService
        });
        
        if (!window.AuthService) {
            console.warn('[DatabaseInit] ⚠️ window.AuthService not found - will fail validation');
        } else {
            console.log('[DatabaseInit] ✅ window.AuthService found');
        }
        
        // Initialize the module
        console.log('[DatabaseInit] Step 4: Calling DatabaseModule.initialize()...');
        console.log('[DatabaseInit] Passing config:', {
            configType: typeof MoneyTrackerDatabaseConfig,
            hasServices: !!MoneyTrackerDatabaseConfig.services,
            servicesState: {
                auth: !!MoneyTrackerDatabaseConfig.services?.auth
            }
        });
        
        const result = await DatabaseModule.initialize(MoneyTrackerDatabaseConfig);
        
        console.log('[DatabaseInit] Initialize result received:', {
            success: result.success,
            hasError: !!result.error,
            error: result.error
        });
        
        if (result.success) {
            console.log('[DatabaseInit] ========== DATABASE MODULE INITIALIZED SUCCESSFULLY ==========');
            console.log('[DatabaseInit] End time:', new Date().toISOString());
            return { success: true };
        } else {
            console.error('[DatabaseInit] ========== DATABASE MODULE INITIALIZATION FAILED ==========');
            console.error('[DatabaseInit] Error:', result.error);
            console.error('[DatabaseInit] End time:', new Date().toISOString());
            throw new Error(result.error || 'Database module initialization failed');
        }
    } catch (error) {
        console.error('[DatabaseInit] ========== DATABASE MODULE INITIALIZATION ERROR ==========');
        console.error('[DatabaseInit] Exception type:', error?.constructor?.name);
        console.error('[DatabaseInit] Exception message:', error?.message);
        console.error('[DatabaseInit] Exception stack:', error?.stack);
        console.error('[DatabaseInit] End time:', new Date().toISOString());
        throw error;
    }
})();

// Also set a flag when complete
window.DatabaseModuleInitPromise.then(() => {
    window.DatabaseModuleInitialized = true;
    console.log('[DatabaseInit] DatabaseModuleInitialized flag set to true');
}).catch(() => {
    window.DatabaseModuleInitialized = false;
    console.error('[DatabaseInit] DatabaseModuleInitialized flag set to false due to error');
});

