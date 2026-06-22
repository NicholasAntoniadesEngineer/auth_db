/**
 * Money Tracker Project-Specific Database Configuration
 * This configures the database module for the money_tracker project.
 * 
 * This file extends DatabaseConfigBase with project-specific values.
 */

// Ensure base config is loaded first
if (typeof DatabaseConfigBase === 'undefined') {
    throw new Error('DatabaseConfigBase must be loaded before MoneyTrackerDatabaseConfig');
}

const MoneyTrackerDatabaseConfig = DatabaseConfigBase.merge({
    provider: {
        type: 'supabase',
        config: {
            // Supabase-specific configuration
            // The actual Supabase client will be created by SupabaseConfig
            // This just identifies the provider type
            // In the future, we could add provider-specific settings here
        }
    },
    
    services: {
        // Auth service will be injected at runtime via DatabaseModule.initialize()
        // It will use window.AuthService for backward compatibility
        auth: null
    },
    
    tables: {
        userMonths: 'user_months',
        exampleMonths: 'example_months',
        settings: 'settings',
        subscriptions: 'subscriptions',
        subscriptionPlans: 'subscription_plans',
        paymentHistory: 'payment_history',
        dataShares: 'data_shares',
        fieldLocks: 'field_locks',
        notifications: 'notifications',
        blockedUsers: 'blocked_users',
        messages: 'messages',
        conversations: 'conversations',
        friends: 'friends'
    },
    
    cache: {
        enabled: true,
        duration: 24 * 60 * 60 * 1000, // 24 hours
        storageKey: 'money_tracker_months_cache',
        timestampKey: 'money_tracker_cache_timestamp'
    },
    
    application: {
        exampleYear: 2045,
        name: 'Money Tracker'
    },
    
    logging: {
        verbose: true,
        prefix: '[Database]'
    }
});

if (typeof window !== 'undefined') {
    window.MoneyTrackerDatabaseConfig = MoneyTrackerDatabaseConfig;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = MoneyTrackerDatabaseConfig;
}

