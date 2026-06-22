/**
 * Password Manager
 *
 * Securely manages temporary password storage for key encryption
 *
 * Security Design:
 * - Password stored ONLY in sessionStorage (cleared on tab close)
 * - Used ONLY for encrypting/decrypting E2E encryption keys
 * - Automatically cleared after use
 * - Never sent to server
 * - Cleared on logout
 *
 * Flow:
 * 1. User logs in → Password stored temporarily
 * 2. Device pairing setup → Use password to encrypt key backup
 * 3. Password cleared immediately after backup created
 * 4. For restoration, user must re-enter password (more secure)
 */

const PasswordManager = {
    STORAGE_KEY: 'money_tracker_temp_password',
    MAX_AGE_MS: 10 * 60 * 1000, // 10 minutes max lifetime

    /**
     * Store password temporarily in sessionStorage
     * Used after successful login to enable key backup
     *
     * @param {string} password - User's password
     */
    storeTemporarily(password) {
        // SM-49: do not log password-handle lifecycle (store/use/age).
        const data = {
            password: password,
            timestamp: Date.now(),
            used: false
        };

        sessionStorage.setItem(this.STORAGE_KEY, JSON.stringify(data));

        // Auto-clear after max age
        setTimeout(() => {
            this.clear();
        }, this.MAX_AGE_MS);
    },

    /**
     * Retrieve temporarily stored password
     * Automatically clears if expired
     *
     * @returns {string|null} Password or null if not available/expired
     */
    retrieve() {
        const dataStr = sessionStorage.getItem(this.STORAGE_KEY);

        if (!dataStr) {
            return null;
        }

        try {
            const data = JSON.parse(dataStr);

            // Check if expired (SM-49: do not log the handle's age/lifecycle).
            const age = Date.now() - data.timestamp;
            if (age > this.MAX_AGE_MS) {
                this.clear();
                return null;
            }

            return data.password;

        } catch (error) {
            console.error('[PasswordManager] Error parsing stored password');
            this.clear();
            return null;
        }
    },

    /**
     * Mark password as used and clear it
     * Called after successfully creating key backup
     */
    markUsedAndClear() {
        // SM-49: silent — do not advertise password-handle lifecycle.
        this.clear();
    },

    /**
     * Clear stored password
     */
    clear() {
        // SM-49: do not log clear-call stack traces or lifecycle messages — they
        // advertise exactly when the temporary password handle is live.
        sessionStorage.removeItem(this.STORAGE_KEY);
    },

    /**
     * Check if password is available
     * @returns {boolean}
     */
    isAvailable() {
        return this.retrieve() !== null;
    },

    /**
     * Prompt user for password if not available
     * Used for key restoration scenarios
     *
     * @param {string} message - Custom prompt message
     * @returns {Promise<string|null>} Password or null if cancelled
     */
    async promptForPassword(message = 'Enter your password to restore encryption keys:') {
        return new Promise((resolve) => {
            // Check if password is already available
            const storedPassword = this.retrieve();
            if (storedPassword) {
                resolve(storedPassword);
                return;
            }

            // Show password prompt
            const password = prompt(message);
            resolve(password);
        });
    },

    /**
     * Verify password by attempting to restore from backup
     * Used to check if entered password is correct
     *
     * @param {string} password - Password to verify
     * @param {string} userId - User ID
     * @returns {Promise<boolean>} True if password is correct
     */
    async verifyPassword(password, userId) {
        try {
            if (!window.KeyBackupService) {
                console.error('[PasswordManager] KeyBackupService not available');
                return false;
            }

            const backup = await window.KeyBackupService.getBackup(userId);
            if (!backup) {
                // No backup exists, can't verify
                return true; // Assume correct (first-time setup)
            }

            // Try to decrypt backup
            const verified = await window.PasswordCrypto.verifyPassword(password, backup);
            return verified;

        } catch (error) {
            console.error('[PasswordManager] Error verifying password:', error);
            return false;
        }
    }
};

// Make available globally
window.PasswordManager = PasswordManager;

// NOTE: Do NOT clear password on page unload - sessionStorage needs to persist across
// page navigations for device pairing to work. Password already has:
// 1. 10-minute expiry timer (MAX_AGE_MS)
// 2. Clear on logout (auth:signout event)
// 3. Automatic clear on tab/window close (sessionStorage behavior)

// Clear password on logout event
window.addEventListener('auth:signout', () => {
    // SM-49: silent — do not advertise password-handle lifecycle.
    PasswordManager.clear();
});
