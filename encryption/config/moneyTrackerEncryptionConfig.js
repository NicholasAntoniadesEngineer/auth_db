/**
 * Money Tracker Project-Specific Encryption Configuration
 * This configures the encryption module for the money_tracker project.
 *
 * This file extends EncryptionConfigBase with project-specific values.
 */

// Ensure base config is loaded first
if (typeof EncryptionConfigBase === 'undefined') {
    throw new Error('EncryptionConfigBase must be loaded before MoneyTrackerEncryptionConfig');
}

const MoneyTrackerEncryptionConfig = EncryptionConfigBase.merge({
    services: {
        // Services will be injected at runtime via EncryptionModule.initialize()
        database: null,
        auth: null,
        subscriptionGuard: null
    },

    crypto: {
        // Self-hosted (SM-11): pinned TweetNaCl 1.0.3 / nacl-util 0.15.1, no third-party CDN.
        naclUrl: '../../shared/vendor/crypto/nacl-fast.min.js',
        naclUtilUrl: '../../shared/vendor/crypto/nacl-util.min.js',
        loadTimeout: 15000,
        hkdf: {
            hash: 'SHA-256',
            infoPrefix: 'MoneyTracker'
        },
        pbkdf2: {
            hash: 'SHA-256',
            iterations: 600000,
            keyLength: 256
        }
    },

    indexedDB: {
        name: 'MoneyTrackerEncryption',
        version: 2,
        stores: {
            identityKeys: 'identity_keys',
            sessionKeys: 'session_keys',
            historicalKeys: 'historical_keys',
            wrapKeys: 'wrap_keys',
            pinnedKeys: 'pinned_keys',
            recvCounters: 'recv_counters'
        }
    },

    tables: {
        identityKeys: 'identity_keys',
        publicKeyHistory: 'public_key_history',
        identityKeyBackups: 'identity_key_backups',
        conversationSessionKeys: 'conversation_session_keys',
        messages: 'messages',
        pairedDevices: 'paired_devices'
    },

    features: {
        // Encryption is available to all users (no tier restriction)
        requiredTier: null
    },

    application: {
        name: 'MoneyTracker',
        safetyNumberGroups: 6,
        safetyNumberDigitsPerGroup: 5
    },

    keyRotation: {
        // Disable auto-rotation - it breaks message decryption when keys change
        // Messages encrypted with old keys cannot be decrypted after rotation
        // Manual rotation can still be triggered if needed
        enabled: false,
        checkOnInit: false
    },

    logging: {
        // Production-safe default: verbose logging off. Enable only behind the
        // explicit local/debug opt-in handled by shared/config/loggingConfig.js.
        verbose: false,
        prefix: '[Encryption]'
    }
});

if (typeof window !== 'undefined') {
    window.MoneyTrackerEncryptionConfig = MoneyTrackerEncryptionConfig;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = MoneyTrackerEncryptionConfig;
}
