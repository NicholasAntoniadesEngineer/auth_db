/**
 * Encryption Error Types
 * Provides typed error classes for precise error handling
 * Eliminates string matching and enables structured error recovery
 */

/**
 * Base class for all encryption-related errors
 */
class EncryptionError extends Error {
    /**
     * @param {string} message - Error message
     * @param {string} code - Error code for programmatic handling
     * @param {boolean} recoverable - Whether the error can potentially be recovered from
     */
    constructor(message, code, recoverable = false) {
        super(message);
        this.name = 'EncryptionError';
        this.code = code;
        this.recoverable = recoverable;
        this.timestamp = new Date().toISOString();
    }

    /**
     * Convert to JSON-serializable object
     */
    toJSON() {
        return {
            name: this.name,
            message: this.message,
            code: this.code,
            recoverable: this.recoverable,
            timestamp: this.timestamp
        };
    }
}

/**
 * Thrown when a required encryption key is not found
 */
class KeyNotFoundError extends EncryptionError {
    /**
     * @param {string} keyType - Type of key (identity, session, historical)
     * @param {string} userId - User ID (optional)
     * @param {number} epoch - Key epoch (optional)
     */
    constructor(keyType, userId = null, epoch = null) {
        const details = [];
        // SM-48: do not embed user-id prefixes in error messages (metadata hygiene).
        if (epoch !== null) details.push(`epoch: ${epoch}`);

        super(
            `${keyType} key not found${details.length ? ` (${details.join(', ')})` : ''}`,
            'KEY_NOT_FOUND',
            true
        );
        this.name = 'KeyNotFoundError';
        this.keyType = keyType;
        this.userId = userId;
        this.epoch = epoch;
    }
}

/**
 * Thrown when local and server keys don't match
 */
class KeyMismatchError extends EncryptionError {
    /**
     * @param {string} message - Error message
     * @param {string} expectedFingerprint - Expected key fingerprint
     * @param {string} actualFingerprint - Actual key fingerprint
     */
    constructor(message = 'Local key does not match server', expectedFingerprint = null, actualFingerprint = null) {
        super(message, 'KEY_MISMATCH', true);
        this.name = 'KeyMismatchError';
        this.expectedFingerprint = expectedFingerprint;
        this.actualFingerprint = actualFingerprint;
    }
}

/**
 * Thrown when decryption fails (wrong key or corrupted data)
 */
class DecryptionError extends EncryptionError {
    /**
     * @param {string} reason - Reason for decryption failure
     * @param {string} context - What was being decrypted (message, session key, backup)
     */
    constructor(reason = 'Decryption failed', context = null) {
        super(
            context ? `${reason} while decrypting ${context}` : reason,
            'DECRYPTION_FAILED',
            false
        );
        this.name = 'DecryptionError';
        this.context = context;
    }
}

/**
 * Thrown when key rotation fails
 */
class KeyRotationError extends EncryptionError {
    /**
     * @param {string} reason - Reason for rotation failure
     * @param {number} currentEpoch - Current key epoch
     */
    constructor(reason, currentEpoch = null) {
        super(reason, 'ROTATION_FAILED', true);
        this.name = 'KeyRotationError';
        this.currentEpoch = currentEpoch;
    }
}

/**
 * Thrown when session key operations fail
 */
class SessionKeyError extends EncryptionError {
    /**
     * @param {string} reason - Reason for session key failure
     * @param {number|string} conversationId - Conversation ID
     * @param {number} epoch - Key epoch
     */
    constructor(reason, conversationId = null, epoch = null) {
        super(reason, 'SESSION_KEY_ERROR', true);
        this.name = 'SessionKeyError';
        this.conversationId = conversationId;
        this.epoch = epoch;
    }
}

/**
 * Thrown when backup restore operations fail
 */
class BackupRestoreError extends EncryptionError {
    /**
     * @param {string} reason - Reason for restore failure
     * @param {string[]} recoveryOptions - Available recovery options
     */
    constructor(reason, recoveryOptions = []) {
        super(reason, 'BACKUP_RESTORE_FAILED', recoveryOptions.length > 0);
        this.name = 'BackupRestoreError';
        this.recoveryOptions = recoveryOptions;
    }
}

/**
 * Thrown when password validation fails
 */
class WeakPasswordError extends EncryptionError {
    /**
     * @param {string[]} feedback - Password strength feedback
     * @param {number} score - Password strength score
     */
    constructor(feedback = [], score = 0) {
        super(
            `Password does not meet security requirements: ${feedback.join('; ')}`,
            'WEAK_PASSWORD',
            true
        );
        this.name = 'WeakPasswordError';
        this.feedback = feedback;
        this.score = score;
    }
}

/**
 * Thrown when a peer's TOFU-pinned identity key (X25519 IK or Ed25519 IK_sig)
 * has CHANGED from the value we previously pinned. This is FAIL-CLOSED: it must
 * propagate so NO session key is derived and no message is sent/decrypted against
 * the new key, until the user verifies the new identity (via the safety number)
 * and explicitly accepts it (KeyManagementService.acceptPeerIdentityChange).
 *
 * A changed identity key is the classic active-MITM / hostile-server signal; the
 * pin only provides enforcement if a change blocks rather than auto-adopts.
 */
class PeerIdentityChangedError extends EncryptionError {
    /**
     * @param {Object} details
     * @param {string} details.userId          - Peer user id whose key changed
     * @param {string} details.oldFingerprint  - Previously pinned fingerprint
     * @param {string} details.newFingerprint  - Newly fetched (rejected) fingerprint
     * @param {string} details.keyType         - 'identity' (X25519 IK) | 'sign' (Ed25519 IK_sig)
     */
    constructor(details = {}) {
        const keyType = details.keyType || 'identity';
        super(
            `Peer identity key changed (${keyType}) - verify the safety number before continuing`,
            'PEER_IDENTITY_CHANGED',
            // Recoverable: the user can accept the change after verifying it.
            true
        );
        this.name = 'PeerIdentityChangedError';
        this.userId = details.userId || null;
        this.oldFingerprint = details.oldFingerprint || null;
        this.newFingerprint = details.newFingerprint || null;
        this.keyType = keyType;
    }

    toJSON() {
        return {
            ...super.toJSON(),
            userId: this.userId,
            oldFingerprint: this.oldFingerprint,
            newFingerprint: this.newFingerprint,
            keyType: this.keyType
        };
    }
}

/**
 * Thrown when device pairing fails
 */
class DevicePairingError extends EncryptionError {
    /**
     * @param {string} reason - Reason for pairing failure
     * @param {boolean} codeExpired - Whether the pairing code expired
     */
    constructor(reason, codeExpired = false) {
        super(reason, 'DEVICE_PAIRING_FAILED', true);
        this.name = 'DevicePairingError';
        this.codeExpired = codeExpired;
    }
}

/**
 * Collection of all encryption error types
 */
const EncryptionErrors = {
    EncryptionError,
    KeyNotFoundError,
    KeyMismatchError,
    DecryptionError,
    KeyRotationError,
    SessionKeyError,
    BackupRestoreError,
    WeakPasswordError,
    PeerIdentityChangedError,
    DevicePairingError,

    /**
     * Check if an error is an encryption error
     * @param {Error} error - Error to check
     * @returns {boolean}
     */
    isEncryptionError(error) {
        return error instanceof EncryptionError;
    },

    /**
     * Create appropriate error from a generic error
     * @param {Error} error - Original error
     * @param {string} context - Context where error occurred
     * @returns {EncryptionError}
     */
    fromError(error, context = null) {
        if (error instanceof EncryptionError) {
            return error;
        }

        // Map common error patterns
        const message = error.message || String(error);

        if (message.includes('Decryption failed') || message.includes('authentication')) {
            return new DecryptionError(message, context);
        }

        if (message.includes('key not found') || message.includes('No backup found')) {
            return new KeyNotFoundError(context || 'unknown', null, null);
        }

        if (message.includes('mismatch')) {
            return new KeyMismatchError(message);
        }

        if (message.includes('password') && message.includes('security')) {
            return new WeakPasswordError([message], 0);
        }

        // Generic encryption error
        return new EncryptionError(message, 'UNKNOWN', false);
    }
};

// Make available globally
if (typeof window !== 'undefined') {
    window.EncryptionErrors = EncryptionErrors;
    // Also expose individual classes
    window.EncryptionError = EncryptionError;
    window.KeyNotFoundError = KeyNotFoundError;
    window.KeyMismatchError = KeyMismatchError;
    window.DecryptionError = DecryptionError;
    window.KeyRotationError = KeyRotationError;
    window.SessionKeyError = SessionKeyError;
    window.BackupRestoreError = BackupRestoreError;
    window.WeakPasswordError = WeakPasswordError;
    window.PeerIdentityChangedError = PeerIdentityChangedError;
    window.DevicePairingError = DevicePairingError;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = EncryptionErrors;
}

console.log('[EncryptionErrors] Error types loaded');
